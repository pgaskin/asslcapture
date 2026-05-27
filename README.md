# asslcapture

Capture system-wide Conscrypt/BoringSSL TLS traffic on Android using eBPF.

Like [ecapture](https://github.com/gojue/ecapture) or [peetch](https://github.com/quarkslab/peetch), but more simple, stable, and focused on Android.

This is a non-intrusive alternative to injecting root certs and generally works more reliably, but requires root and a modern kernel.

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

### Why not ecapture

This tool handles many edge-cases which ecapture will not:

- Kernels with broken/non-functional bpf_probe_read_user.
- Kernels with a primitive verifier which can't properly handle dynamic read lengths.
- Applications using a copy of BoringSSL other than the one in the conscrypt APEX, including statically-linked ones.
- Automatic offset extraction, no hard-coded offsets.
- Mitigating race conditions around the pcapng output.
- Capturing keys from incomplete TLS handshakes.

This tool has a fundamentally different architecture:

- It uses a more reliable hooking point.
- It does not attempt to capture packets before they hit the network layer (which brings a lot more problems and edge-cases with it).
- It does not attempt to decode layer 3+ protocols during packet capture, avoiding a lot of bugs around that (use a tool built for that like wireshark or pcapng-utils), and allowing it to support other protocols like GRPC.
- It has a much simpler, and reproducible, build process for the uprobe bpf.
- It has explicit buffering logic, resulting in significantly fewer dropped packets, even under load.
- It is much more modular.

And it doesn't have any of ecapture's problems:

- The 1.x ecapture versions have extremely limited version support.
- The 2.x ecapture versions went all-in on LLM usage for coding, refactoring, code review, support, documentation, etc.
- Lots of undocumented edge-cases and bugs.
- Pretty much every 2.x version has had a bug or regression on Android, making it basically useless.
- Extremely complex and non-reproducible build process with host dependencies.
- Unnecessary complexity due to supporting application-level protocol parsing, library-level stream capture, and non-TLS stuff.
- Lots of duplicate code paths with subtle differences by output format (text, pcap, sslkeylog) and tls library, each with their own issues.

### Library locations

On Android, BoringSSL is usually wrapped with conscrypt (for usage from Java), which may come from:

- Loadable GMS module (before Android 4.1).
- The system conscrypt (before Android 10).
- Mainline conscrypt APEX (Android 10+).
- Apps (via `org.conscrypt:conscrypt-android`).

Some apps use BoringSSL natively by statically linking it, including:

- Chromium/Chrome.

If BoringSSL cannot be detected, keys will not be logged for connections from that application.
