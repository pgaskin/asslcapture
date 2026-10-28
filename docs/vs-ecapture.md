## Why not ecapture?

> [!NOTE]
> This was written on May 30, 2026, and was accurate at that time.
>
> Since then, as of [ecapture v2.9.0](https://github.com/gojue/ecapture/releases/tag/v2.9.0), they seem to have significantly improved the quality and architecture, especially around buffering and modularity, and fixed many of the bugs.
>
> They seem to have taken inspiration from asslcapture (or come to the same design independently, since asslcapture kind of has the optimal design for this sort of tool), as parts of it are now eerily similar to ours. The output path is now independent from the capture path, has separate paths for each format, buffers keylogs separately from packets with somewhat improved buffering design, and is more efficient than before ([gojue/ecapture#953](https://github.com/gojue/ecapture/pull/953), [gojue/ecapture#1049](https://github.com/gojue/ecapture/pull/1049), [gojue/ecapture#1051](https://github.com/gojue/ecapture/pull/1051), [gojue/ecapture#1052](https://github.com/gojue/ecapture/pull/1052), [gojue/ecapture#1055](https://github.com/gojue/ecapture/pull/1055), others). In addition, the boringssl capture has been redesigned to work more like asslcapture and requires fewer offsets, now having dynamic offset extraction, though it still isn't as robust as asslcapture and can't handle ones without symbols or which are statically linked ([gojue/ecapture#1047](https://github.com/gojue/ecapture/pull/1047), others). They have also fixed a bunch of the silly bugs (e.g., missing newlines in keylogs, random typos in offset stuff, btf handling bugs, missed flushes on buffers, off-by-one issues, mishandling tagged pointers, etc), and there seems to now be a bit more oversight for the AI-assisted PRs.
>
> I haven't tested it yet, so I can't say how well it actually works, but the code and overally design looks much better than before. Nevertheless, asslcapture is still the only tool which properly supports statically linked or stripped boringssl, is also much simpler to build, and still has a cleaner design (partly due to it being much more focused on Android and BoringSSL). Still, ecapture seems to have improved significantly overally and might be a good option if you need to capture other TLS libraries.

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

Unlike ecapture, it also supports kernels without eBPF support using ptrace.
