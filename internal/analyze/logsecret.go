// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package analyze

import (
	"debug/elf"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

var keylogLabels = []string{
	"CLIENT_RANDOM",
	"CLIENT_EARLY_TRAFFIC_SECRET",
	"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
	"SERVER_HANDSHAKE_TRAFFIC_SECRET",
	"CLIENT_TRAFFIC_SECRET_0",
	"SERVER_TRAFFIC_SECRET_0",
	"EXPORTER_SECRET",
}

// FindLogSecret finds the file offset of bssl::ssl_log_secret, which is called
// with the arguments:
//
//	x0: SSL* ssl (i.e., ssl_st*)
//	x1: const char *label
//	x2: const uint8_t *secret
//	x3: const size_t secret_len
//
// This function conditionally calls the ssl keylog callback and build the
// keylog line to append to the sslkeylogfile, and has existed since 2016 with
// very few changes over time. The symbol is not exported, but the function
// itself always exists even when statically linked (e.g., into libchrome).
//
// Note that x2/x3 were separate arguments at one point, then a Span<const
// uint8_t> (backed by SpanStorage<T, dynamic_extent>) in newer versions, but
// they end up being passed the same way.
//
// Before TLS 1.3 support was implemented in 2016, this was called
// ssl_log_master_secret, but it's old enough, we can safely ignore it for
// simplicity.
//
// The CLIENT_RANDOM to identify the keylog line is taken from
// ssl->s3->client_random.
//
// See `git log -S 'ssl_log_secret'`.
func FindLogSecret(ef *elf.File) (fileOffset uint64, warn []error, err error) {
	if err := checkARM64(ef); err != nil {
		return 0, nil, err
	}
	var errs []error
	if fileOffset, err := FindLogSecretMiniDebug(ef); err != nil {
		errs = append(errs, fmt.Errorf("minidebuginfo: %w", err))
	} else {
		return fileOffset, warn, nil
	}
	if fileOffset, candidates, err := FindLogSecretHeuristic(ef); err != nil {
		errs = append(errs, fmt.Errorf("heuristic: %w", err))
	} else {
		for label, o := range candidates {
			if len(o) == 0 {
				warn = append(warn, fmt.Errorf("no ssl_log_secret call found for %s, keylog may be incomplete", label))
			}
		}
		return fileOffset, warn, nil
	}
	return 0, nil, fmt.Errorf("failed to find bssl::ssl_log_secret function: %w", errors.Join(errs...))
}

// FindLogSecretHeuristic finds ssl_log_secret by looking for a compatible
// symbol in the MiniDebugInfo. This works on most dynamic libssl.so binaries,
// including the one shipped in Android (system or APEX) and the one in the
// org.conscrypt:conscrypt-android library.
func FindLogSecretMiniDebug(ef *elf.File) (fileOffset uint64, err error) {
	if err := checkARM64(ef); err != nil {
		return 0, err
	}

	segments, err := readSegments(ef)
	if err != nil {
		return 0, err
	}

	syms, err := readMiniDebugInfo(ef)
	if err != nil {
		return 0, err
	}

	i := slices.IndexFunc(syms, func(sym elf.Symbol) bool {
		// bssl::ssl_log_secret(ssl_st const*, char const*, bssl::Span<unsigned char const>)
		if sym.Name == "_ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE" {
			return true
		}

		// bssl::ssl_log_secret(ssl_st const*, char const*, unsigned char const*, unsigned long)
		if sym.Name == "_ZN4bssl14ssl_log_secretEPK6ssl_stPKcPKhm" {
			return true // legacy
		}

		return false
	})
	if i == -1 {
		for _, sym := range syms {
			if strings.HasPrefix(sym.Name, "_ZN4bssl14ssl_log_secret") {
				return 0, fmt.Errorf("incompatible bssl::ssl_log_secret %q", sym.Name)
			}
		}
		return 0, fmt.Errorf("no bssl::ssl_log_secret symbol found")
	}
	vaddr := syms[i].Value

	fileOffset, ok := segments.FileOffset(vaddr)
	if !ok {
		return 0, fmt.Errorf("could not map virtual address 0x%x to a file offset", vaddr)
	}
	return fileOffset, nil
}

// FindLogSecretHeuristic finds ssl_log_secret by looking for
// ssl_log_secret(ssl, label, ...) calls where label is a constant string
// reference to a valid keylog secret label.
func FindLogSecretHeuristic(ef *elf.File) (fileOffset uint64, candidates map[string][]uint64, err error) {
	if err := checkARM64(ef); err != nil {
		return 0, nil, err
	}

	segments, err := readSegments(ef)
	if err != nil {
		return 0, nil, err
	}

	// find known sslkeylogfile secret labels
	addrLabel := make(map[uint64]string)
	for _, label := range keylogLabels {
		for _, sec := range segments {
			for i := range findNullString(sec.Data, label) {
				addrLabel[sec.Addr+uint64(i)] = label
			}
		}
	}

	// keep track of possible ssl_log_secret calls for each label
	candidates = make(map[string][]uint64)
	for _, label := range keylogLabels {
		candidates[label] = []uint64{}
	}

	// enumerate all basic blocks in the lib to find all function
	// calls/tail-calls with a constant second argument being a secret label
	//
	// this works since it's unlikely to get inlined (I've never seen it happen
	// yet in conscrypt or libchrome) since it's used in multiple places and
	// non-trivial, and it's not going to get split since each label is constant
	// and only ever used once (so the compiler will load it directly into the
	// x1 register)
	//
	// this symbolic execution is very rudimentary and will usually have
	// incorrect register values, but that's fine since we have a set of
	// specific ones we're looking for in a specific pattern
	for _, segment := range segments {
		if !segment.Exec {
			continue
		}
		var rv regValues
		for i := 0; i+4 <= len(segment.Data); i += 4 {
			rv.pc = segment.Addr + uint64(i)

			inst, err := arm64asm.Decode(segment.Data[i:])
			if err != nil {
				continue
			}

			switch inst.Op {
			case arm64asm.ADRP:
				if dst, ok := argReg(inst.Args[0]); ok {
					if rel, ok := inst.Args[1].(arm64asm.PCRel); ok {
						rv.Set(dst, (rv.pc&^uint64(0xFFF))+uint64(rel))
					} else {
						rv.Clear(dst)
					}
				}

			case arm64asm.ADR:
				if dst, ok := argReg(inst.Args[0]); ok {
					if rel, ok := inst.Args[1].(arm64asm.PCRel); ok {
						rv.Set(dst, rv.pc+uint64(rel))
					} else {
						rv.Clear(dst)
					}
				}

			case arm64asm.ADD:
				if dst, ok := argReg(inst.Args[0]); ok {
					src, srcOK := argReg(inst.Args[1])
					imm, immOK := immVal(inst.Args[2])
					if srcOK && immOK {
						if v, ok := rv.Get(src); ok {
							rv.Set(dst, v+imm)
							break
						}
					}
					rv.Clear(dst)
				}

			case arm64asm.BL, arm64asm.BLR, arm64asm.B, arm64asm.BR:
				var target uint64
				switch inst.Op {
				case arm64asm.BL, arm64asm.B: // pc-relative
					// conditional branches will have an [arm64asm.Cond] as the first arg
					if rel, ok := inst.Args[0].(arm64asm.PCRel); ok {
						target = uint64(int64(rv.pc) + int64(rel))
					}
				case arm64asm.BLR, arm64asm.BR: // to register
					if reg, ok := argReg(inst.Args[0]); ok {
						target, _ = rv.Get(reg)
					}
				}
				if target != 0 {
					if x1, ok := rv.Get(arm64asm.X1); ok {
						if label, ok := addrLabel[x1]; ok {
							candidates[label] = append(candidates[label], target)
						}
					}
				}
				rv.ClearAll()

			case arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ, arm64asm.RET:
				rv.ClearAll()
			}
		}
	}

	// use the CLIENT_RANDOM one as the canonical address
	cr := candidates["CLIENT_RANDOM"]
	if len(cr) == 0 {
		return 0, candidates, fmt.Errorf("no offset found for ssl_log_secret(ssl, CLIENT_RANDOM, ...)")
	}
	if len(cr) != 1 {
		return 0, candidates, fmt.Errorf("found multiple candidate offsets for ssl_log_secret(ssl, CLIENT_RANDOM, ...): %#x", cr)
	}
	vaddr := cr[0]

	for _, label := range keylogLabels {
		addrs := candidates[label]
		if len(addrs) == 0 {
			continue // ignore missing ones, might be an old version (and we can warn about these later)
		}
		if !slices.Contains(addrs, vaddr) {
			return 0, candidates, fmt.Errorf("expected offset 0x%x for ssl_log_secret(ssl, %s, ...), got %v", vaddr, label, addrs)
		}
	}

	// map the virtual address back to a file offset
	fileOffset, ok := segments.FileOffset(vaddr)
	if !ok {
		return 0, candidates, fmt.Errorf("could not map virtual address 0x%x to a file offset", vaddr)
	}
	return fileOffset, candidates, nil
}
