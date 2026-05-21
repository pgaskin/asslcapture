// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package analyze statically analyzes the ARM64 BoringSSL libssl.so (or
// binaries linking it statically) to find offsets for logging TLS secrets.
//
// I asked claude to pull a bunch of conscrypt versions since 2017 from maven
// and also look at the source code (directly and with clang), disassembly
// (using llvm-objdump), and the results of running [FindLogSecret] and
// [FindClientRandom] (I'm only using claude for testing, not for writing the
// logic, since I don't trust it enough for that and it's more fun to do it
// myself anyways), and it gave the following:
//
//	s3 offset history in ssl_st / SSLConnection
//	============================================
//
//	RC2 / RC8    Mar–Jun 2017    s3 = 72
//	  method*(8) + int version(4) + max_version(2) + min_version(2) +
//	  max_send_frag(2) + pad(6) + rbio*(8) + wbio*(8) + handshake_func*(8) +
//	  init_buf*(8) + init_msg*(8) + init_num(4) + pad(4)
//
//	RC10         Sep 2017        s3 = 56     (-16)
//	  8f36c51f9: int version → uint16_t; 4×u16 now pack without padding (-8)
//	  7934f08b2: remove init_msg*(8) + init_num(4)+pad(4) (-16),
//	             add tls13_variant enum(4)+pad(2+2) (+8)
//
//	RC13/RC14    Nov–Dec 2017    s3 = 48     (-8)
//	  32ce0ac0d: remove init_buf*(8)
//
//	1.0.0        Feb 2018        s3 = 40     (-8)
//	  2f9b47fb1: move tls13_variant enum out to SSL3_STATE (-4-2pad-2pad)
//
//	1.4.2+       Dec 2018–now    s3 = 48     (+8)
//	  b7bc80a9a: introduce SSL_CONFIG; move version fields into it,
//	             insert UniquePtr<SSL_CONFIG>(8) before max_send_frag,
//	             which now stands alone and creates 6 bytes of padding
//
//	SSL3_STATE.client_random = 48 throughout (read_seq(8) + write_seq(8) + server_random(32))
//	SSL3_RANDOM_SIZE = 32 since the initial BoringSSL import, fixed by the TLS wire format
//
// I've also manually tested this agains a bunch of libchrome.so versions and
// libssl.so from vendor firmware, aosp, and the mainline conscrypt apex.
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

// ldrImmVal returns the base register and immediate offset of a MemImmediate
// AddrOffset arg (i.e., [base, #imm] addressing) by parsing its string form
// (the actual values are in unexported fields).
func ldrImmVal(arg arm64asm.Arg) (base arm64asm.Reg, offset int64, ok bool) {
	m, isMemImm := arg.(arm64asm.MemImmediate)
	if !isMemImm || m.Mode != arm64asm.AddrOffset {
		return 0, 0, false
	}
	s := strings.TrimPrefix(m.String(), "[")
	s = strings.TrimSuffix(s, "]")
	_, immPart, hasImm := strings.Cut(s, ",")
	if !hasImm {
		return arm64asm.Reg(m.Base), 0, true
	}
	immPart = strings.TrimPrefix(immPart, "#")
	n, err := strconv.ParseInt(immPart, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return arm64asm.Reg(m.Base), n, true
}

// memExtendVal returns the base and index registers of a MemExtend arg (i.e.,
// [base, index] or [base, index, extend #amount]).
func memExtendVal(arg arm64asm.Arg) (base, index arm64asm.Reg, ok bool) {
	m, isMemExtend := arg.(arm64asm.MemExtend)
	if !isMemExtend {
		return 0, 0, false
	}
	return arm64asm.Reg(m.Base), m.Index, true
}
