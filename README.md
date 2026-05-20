# asslcapture

Capture system-wide Conscrypt/BoringSSL TLS traffic on Android using eBPF.

Like [ecapture](https://github.com/gojue/ecapture), but more simple, focused, and stable.

This is a non-intrusive alternative to injecting root certs and generally works more reliably, but requires root and a modern kernel.

### Goals

- Readable, non-vibecoded, and simple code.
- Explicit focus on Android with boringssl and a modern kernel version.
- Wide boringssl version compatibility.
- Other native TLS libraries which apps may embed are out-of-scope (for now at least) (this is pretty rare, though).
- Comprehensive automated testing.
- Only basic output formats, no application protocol parsing for simplicity:
  - [SSLKEYLOGFILE](https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html).
  - [PCAPNG](https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html) with [dsb](https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html#name-decryption-secrets-block).
- Wireshark [extcap](https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html) integration?

### Why not ecapture

- The 1.x versions have extremely limited version support.
- The 2.x versions went all-in on LLM usage for coding, refactoring, code review, support, documentation, etc.
- Lots of undocumented edge-cases and bugs.
- Pretty much every 2.x version has had a bug or regression on Android, making it basically useless.
  - Missing library support.
  - Failed library detection.
  - Logic bugs since most of it was written for non-Android.
  - Silently dropped traffic.
  - Silently ignored traffic.
  - Broken output writing (e.g., missing key material).
- Extremely complex and non-reproducible build process with host dependencies.
- Unnecessary complexity due to supporting application-level protocol parsing and non-TLS stuff.

### Library locations

On Android, BoringSSL is usually bundled with conscrypt, which may come from:

- Loadable GMS module (before Android 4.1).
- The system conscrypt (before Android 10).
- Mainline conscrypt APEX (Android 10+).
- Apps (via `org.conscrypt:conscrypt-android`).
