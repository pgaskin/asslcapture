## Why not ecapture?

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
