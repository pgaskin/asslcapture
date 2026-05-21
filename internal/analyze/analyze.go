// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package analyze statically analyzes the ARM64 BoringSSL libssl.so (or
// binaries linking it statically) to find offsets for logging TLS secrets.
package analyze

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	"strconv"
	"strings"

	"github.com/ulikunitz/xz"
	"golang.org/x/arch/arm64/arm64asm"
)

// findNullString iterates over all indexes of data with s as a null-terminated
// UTF-8 string.
func findNullString(data []byte, s string) iter.Seq[int] {
	return func(yield func(int) bool) {
		needle := []byte(s)
		for i := 0; ; {
			j := bytes.Index(data[i:], needle)
			if j < 0 {
				return
			}
			idx := i + j
			end := idx + len(needle)
			if end >= len(data) || data[end] == 0 {
				if !yield(idx) {
					return
				}
			}
			i = idx + 1
		}
	}
}

// checkARM64 returns an error if ef is not a ARM64 binary.
func checkARM64(ef *elf.File) error {
	if ef.Machine != elf.EM_AARCH64 {
		return fmt.Errorf("%s is not an arm64 elf", ef.Machine)
	}
	if ef.ByteOrder != binary.LittleEndian {
		return fmt.Errorf("elf is not little-endian")
	}
	return nil
}

// readMiniDebugInfo reads the GNU [MiniDebugInfo] from ef, which contains a
// mapping of symbol names to virtual addresses typically used for backtraces.
//
// [MiniDebugInfo]:
// https://sourceware.org/gdb/current/onlinedocs/gdb.html/MiniDebugInfo.html
func readMiniDebugInfo(ef *elf.File) ([]elf.Symbol, error) {
	const section = ".gnu_debugdata"

	s := ef.Section(section)
	if s == nil {
		return nil, fmt.Errorf("no %s section", section)
	}

	zr, err := xz.NewReader(s.Open())
	if err != nil {
		return nil, fmt.Errorf("decompress %s: %w", section, err)
	}

	e, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("decompress %s: %w", section, err)
	}

	ef2, err := elf.NewFile(bytes.NewReader(e))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", section, err)
	}

	syms, err := ef2.Symbols()
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", section, err)
	}
	return syms, nil
}

// loadSegments keeps track of PT_LOAD segments and maps offsets.
type loadSegments []loadSegment

type loadSegment struct {
	Addr   uint64
	Offset uint64
	Data   []byte
	Exec   bool
}

func readSegments(ef *elf.File) (loadSegments, error) {
	var segments loadSegments
	for _, prog := range ef.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_R == 0 {
			continue
		}
		data, err := io.ReadAll(prog.Open())
		if err != nil {
			return segments, err
		}
		segments = append(segments, loadSegment{
			Addr:   prog.Vaddr,
			Offset: prog.Off,
			Data:   data,
			Exec:   prog.Flags&elf.PF_X != 0,
		})
	}
	return segments, nil
}

func (s loadSegments) FileOffset(vaddr uint64) (uint64, bool) {
	for _, prog := range s {
		if vaddr >= prog.Addr && vaddr < prog.Addr+uint64(len(prog.Data)) {
			return vaddr - prog.Addr + prog.Offset, true
		}
	}
	return 0, false
}

// regValues keeps track of constant 64-bit register values (x0-x29).
type regValues struct {
	regs  [30]uint64
	known [30]bool
	pc    uint64
}

func (rv *regValues) index(r arm64asm.Reg) (int, bool) {
	if r >= arm64asm.X0 && r <= arm64asm.X29 {
		return int(r - arm64asm.X0), true
	}
	return -1, false
}

func (rv *regValues) Set(r arm64asm.Reg, v uint64) bool {
	if i, ok := rv.index(r); ok {
		rv.regs[i] = v
		rv.known[i] = true
		return true
	}
	return false
}

func (rv *regValues) Clear(r arm64asm.Reg) bool {
	if i, ok := rv.index(r); ok {
		rv.known[i] = false
		return true
	}
	return false
}

func (rv *regValues) ClearAll() {
	rv.known = [30]bool{}
}

func (rv *regValues) Get(r arm64asm.Reg) (uint64, bool) {
	if i, ok := rv.index(r); ok {
		return rv.regs[i], rv.known[i]
	}
	return 0, false
}

// argReg gets the register for an arg.
func argReg(arg arm64asm.Arg) (arm64asm.Reg, bool) {
	switch v := arg.(type) {
	case arm64asm.Reg:
		return v, true
	case arm64asm.RegSP:
		return arm64asm.Reg(v), true
	}
	return 0, false
}

// immVal returns the value of an immediate or shifted immediate.
func immVal(arg arm64asm.Arg) (uint64, bool) {
	switch v := arg.(type) {
	case arm64asm.Imm:
		return uint64(v.Imm), true
	case arm64asm.ImmShift:
		return immShiftVal(v)
	}
	return 0, false
}

// immShiftVal computes the value of a shifted immediate by parsing its string
// form (the actual values are in unexported fields).
func immShiftVal(v arm64asm.ImmShift) (uint64, bool) {
	s := strings.TrimPrefix(v.String(), "#")
	if baseStr, shiftStr, ok := strings.Cut(s, ", LSL #"); ok {
		base, err1 := strconv.ParseUint(baseStr, 0, 64)
		shift, err2 := strconv.ParseUint(shiftStr, 10, 8)
		if err1 != nil || err2 != nil {
			return 0, false
		}
		return base << shift, true
	}
	if baseStr, shiftStr, ok := strings.Cut(s, ", MSL #"); ok {
		base, err1 := strconv.ParseUint(baseStr, 0, 64)
		shift, err2 := strconv.ParseUint(shiftStr, 10, 8)
		if err1 != nil || err2 != nil {
			return 0, false
		}
		return (base << shift) | ((1 << shift) - 1), true
	}
	n, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
