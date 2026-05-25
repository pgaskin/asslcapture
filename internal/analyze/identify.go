// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package analyze

import (
	"bytes"
	"debug/elf"
	"io"
	"slices"
)

// IsProbablyLinkedBoringSSL checks if ef probably links BoringSSL, meaning it
// probably doesn't embed it. This isn't perfect, and is intended to be used as
// an optmization to avoid scanning large binaries unnecessarily.
//
// An example of this is the libmainlinecronet in the com.android.tethering
// APEX. While cronet is usually compiled with BoringSSL statically linked
// (e.g., libcronet in most Google apps), this one has stable_cronet_libssl.so
// separately.
func IsProbablyLinkedBoringSSL(ef *elf.File) bool {
	var any, defined bool
	if syms, err := ef.DynamicSymbols(); err == nil {
		for _, sym := range syms {
			switch sym.Name {
			case "SSL_new", "SSL_CTX_new":
				if sym.Section != elf.SHN_UNDEF {
					defined = true
				}
				any = true
			}
		}
	}
	return any && !defined
}

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

// IsMaybeBoringSSL searches the mapped segments for strings related to
// BoringSSL. If it returns false, it probably isn't BoringSSL.
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
