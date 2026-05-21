// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package analyze

import (
	"bytes"
	"debug/elf"
	"io"
	"slices"
)

var boringsslStrings = [][]string{
	{
		"unknown PSK identity",
		"unknown signature algorithm",
		"unknown pkey:%d hash:%s",
	},
	{
		"TLS_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_PSK_WITH_AES_128_CBC_SHA",
	},
	{
		"certificate expired",
		"certificate required",
		"certificate revoked",
	},
}

func IsMaybeBoringSSL(ef *elf.File) (bool, error) {
	if err := checkARM64(ef); err != nil {
		return false, err
	}
	have := make([]bool, len(boringsslStrings))
	for _, prog := range ef.Progs {
		// note: don't filter out executable segments; some libs (like cronet) put the strings in there
		if prog.Flags&elf.PF_R == 0 {
			continue
		}
		buf, err := io.ReadAll(prog.Open())
		if err != nil {
			return false, err
		}
		for i, ss := range boringsslStrings {
			if have[i] {
				continue
			}
			for _, s := range ss {
				if bytes.Contains(buf, []byte(s)) {
					have[i] = true
					break
				}
			}
		}
		if !slices.Contains(have, false) {
			return true, nil
		}
	}
	return false, nil
}
