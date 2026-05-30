# asslcapture

Capture system-wide Conscrypt/BoringSSL TLS traffic on Android using eBPF.

Like [ecapture](https://github.com/gojue/ecapture) or [peetch](https://github.com/quarkslab/peetch), but more simple, stable, and focused on Android.

This is a non-intrusive alternative to injecting root certs and generally works more reliably, but requires root and a modern kernel.

See [here](./docs/vs-ecapture.md) for a comparison to ecapture.

### Features

- Readable, non-vibecoded, and simple code.
- Focus on ARM64. ARMv7 support might be added later.
- Explicit focus on Android with boringssl and a non-ancient kernel version.
- Partial support for older kernels using ptrace or a more limited version of the probe.
- Wide boringssl version compatibility with automated offset analysis.
- Other native TLS libraries which apps may embed are out-of-scope (for now at least) (this is pretty rare, though).
- Only basic output formats, no application protocol parsing for simplicity (use [Wireshark](https://www.wireshark.org/) or something like [pcapng_to_har](https://pts-project.org/pcapng-utils/) if you want to look at HTTP traffic):
  - [SSLKEYLOGFILE](https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html).
  - [PCAPNG](https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html) with [dsb](https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html#name-decryption-secrets-block).
- Support for multiple copies of BoringSSL, including ones statically linked into apps.
- Carefully designed buffering to avoid dropped packets/secrets.

### Documentation

- [Build](./docs/build.md)
- [Troubleshooting](./docs/troubleshooting.md)
- [Usage](./docs/usage.md)
- [Comparison to ecapture](./docs/vs-ecapture.md)
