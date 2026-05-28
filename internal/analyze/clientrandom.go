// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package analyze

import (
	"debug/elf"
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"
)

// ClientRandomSize is SSL3_RANDOM_SIZE.
const ClientRandomSize = 32

// ClientRandom infers the offset of s3->client_random within ssl_st from the
// ssl_log_secret implementation.
//
// Internally, the ssl_log_secret will call cbb_add_hex_consttime(cbb,
// ssl->s3->client_random), which may be inlined. Both ssl and s3 are pointers,
// and client_random is a byte array of length [ClientRandomSize].
func ClientRandom(ef *elf.File, offset uint64) (s3, clientRandom int, err error) {
	if err := checkARM64(ef); err != nil {
		return 0, 0, err
	}
	segments, err := readSegments(ef)
	if err != nil {
		return 0, 0, err
	}

	var text []byte
	for _, seg := range segments {
		if !seg.Exec {
			continue
		}
		if offset >= seg.Offset && offset < seg.Offset+uint64(len(seg.Data)) {
			text = seg.Data[offset-seg.Offset:]
			break
		}
	}
	if text == nil {
		return 0, 0, fmt.Errorf("file offset 0x%x not found in any executable segment", offset)
	}

	// we shouldn't need to do full control flow analysis since the function is
	// designed to be constant time and the only branches will be failed cbb
	// appends, which all result in an early return (so it should be compiled to
	// a single block which gets jumped to when a cbb append returns false), so
	// the dereferences should be close together
	//
	// however, as a result of this, we do set a fixed size of instructions to
	// disassemble since returns may be in the middle. This should be fine since
	// the general implementation of this function has not changed
	var insts []arm64asm.Inst
	for i := 0; i+4 <= len(text) && len(insts) < 512; i += 4 {
		if inst, err := arm64asm.Decode(text[i:]); err != nil {
			insts = append(insts, arm64asm.Inst{})
		} else {
			insts = append(insts, inst)
		}
	}

	// look for the two consecutive deferences, which will be something like:
	//
	//	ldr xN, [x?, #s3_off]
	//	add xP, xN, #cr_off
	//	cbb_add_hex_consttime(?, xP)
	for i, ii := range insts {
		if ii.Op == 0 {
			continue // invalid
		}
		if ii.Op != arm64asm.LDR {
			continue
		}
		ldrDst, ok := argReg(ii.Args[0])
		if !ok || ldrDst < arm64asm.X0 || ldrDst > arm64asm.X29 {
			continue
		}
		_, s3Off, ok := ldrImmVal(ii.Args[1])
		if !ok || s3Off < 0 {
			continue
		}
		for j := i + 1; j < len(insts) && j <= i+20; j++ {
			jj := insts[j]
			if jj.Op == 0 {
				continue // invalid
			}
			if jj.Op == arm64asm.ADD {
				addDst, addDstOK := argReg(jj.Args[0])
				addSrc, addSrcOK := argReg(jj.Args[1])
				crVal, crOK := immVal(jj.Args[2])
				if addDstOK && addSrcOK && crOK && addSrc == ldrDst {
					// if cbb_add_hex_consttime is not inlined:
					//
					//	add x1, xN, #cr_off
					//	... up to ~3 instructions
					//	bl ?
					if addDst == arm64asm.X1 {
						for k := j + 1; k < len(insts) && k <= j+3; k++ {
							if insts[k].Op != 0 && insts[k].Op == arm64asm.BL {
								return int(s3Off), int(crVal), nil
							}
						}
					}

					// if inlined:
					//
					//	add xP, xN, #cr_off
					//	... up to ~8 instructions
					//	ldrb w?, [xP, X?] or ldrb w?, [xP] or ldrb w?, [xP, #imm]
					for k := j + 1; k < len(insts) && k <= j+8; k++ {
						kk := insts[k]
						if kk.Op == 0 || kk.Op != arm64asm.LDRB {
							continue
						}
						if base, _, ok := memExtendVal(kk.Args[1]); ok && base == addDst {
							return int(s3Off), int(crVal), nil
						}
						if base, _, ok := ldrImmVal(kk.Args[1]); ok && base == addDst {
							return int(s3Off), int(crVal), nil
						}
					}
				}
			}
			if dst, ok := argReg(jj.Args[0]); ok && dst == ldrDst {
				break // ldr dst probably clobbered
			}
		}
	}

	return 0, 0, fmt.Errorf("could not find client_random offset in ssl_log_secret at file offset 0x%x", offset)
}
