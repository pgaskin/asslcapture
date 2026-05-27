# asslcapture

Capture system-wide Conscrypt/BoringSSL TLS traffic on Android using eBPF.

Like [ecapture](https://github.com/gojue/ecapture) or [peetch](https://github.com/quarkslab/peetch), but more simple, stable, and focused on Android.

This is a non-intrusive alternative to injecting root certs and generally works more reliably, but requires root and a modern kernel.

See [here](./docs/vs-ecapture.md) for a comparison to ecapture.

### Goals

- Readable, non-vibecoded, and simple code.
- Explicit focus on Android with boringssl and a non-ancient kernel version (4.1+).
- Wide boringssl version compatibility.
- Other native TLS libraries which apps may embed are out-of-scope (for now at least) (this is pretty rare, though).
- Comprehensive automated testing.
- Only basic output formats, no application protocol parsing for simplicity (use [Wireshark](https://www.wireshark.org/) or something like [pcapng_to_har](https://pts-project.org/pcapng-utils/) if you want to look at HTTP traffic):
  - [SSLKEYLOGFILE](https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html).
  - [PCAPNG](https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html) with [dsb](https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html#name-decryption-secrets-block).
- Wireshark [extcap](https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html) integration?
- Packet capture via a TC filter (so we get process info).

### Library locations

On Android, BoringSSL is usually wrapped with conscrypt (for usage from Java), which may come from:

- Loadable GMS module (before Android 4.1).
- The system conscrypt (before Android 10).
- Mainline conscrypt APEX (Android 10+).
- Apps (via `org.conscrypt:conscrypt-android`).

Some apps use BoringSSL natively by statically linking it, including:

- Chromium/Chrome.

If BoringSSL cannot be detected, keys will not be logged for connections from that application.
