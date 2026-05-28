## Usage

You will need to push the asslcapture binary to your device and run it as root. The following examples assume you have a working `su` binary. If you have rooted ADB, just run the commands directly.

These are just examples. For full usage information, see `--help`.

```
usage: asslcapture [options]

GENERAL OPTIONS
  -v, --verbose   enable debug output
  -h, --help      show this help text
      --exit-eof  exit cleanly when eof received on stdin (useful if running directly with shell_v2 since it can send
                  eof, but not signals)

ANALYSIS OPTIONS
  -D, --ignore-dbginfo  ignore debug info, force full analysis

SCAN OPTIONS
  -c, --cache filename    save and load information about scanned libs to this file
  -s, --scan              alias for a sensible combination of scan options (currently --scan-libs-sys --scan-libs-app)
  -l, --scan-lib spec     scan a single elf file (/path/to/libssl.so), all libs in a zip file (/path/to/app.apk), or a
                          specific lib in a zip file (/path/to/app.apk!/lib/arm64-v8a/libssl.so) (can be specified
                          multiple times)
      --scan-libs dir     scan for libraries in a directory (using heuristics on the name) (can be specified multiple
                          times)
      --scan-libs-sys     scan for libraries in standard lib dirs
      --scan-libs-app     scan for libraries in standard app dirs
      --scan-workers int  number of concurrent analyses to run (default: GOMAXPROCS) (default: 8)

PROBE OPTIONS
      --probe-buffer int  number of uprobe events to buffer before dropping (default: 64)
  -R, --probe-noread      use process_vm_readv to read from userspace instead of bpf_probe_read_user (may work better on
                          old kernels, but slightly racy)

CAPTURE OPTIONS
  -m, --capture mode                   capture mode (if not specified, only scans then exits) (keylog, pcapng)
  -o, --capture-output filename        output filename (default stdout)
  -f, --capture-filter str             tcpdump-style capture filter (does not affect keylog)
  -i, --capture-interface str          interface name to capture packets from (does not affect keylog) (default: "any")
      --capture-buffer-delay duration  delay packets by this amount of time to give time for keys to be logged first
                                       (does not affect keylog) (default: 25ms)
      --capture-buffer-pktsize int     size for pre-allocated packet buffers (oversized will be significantly less
                                       efficient) (does not affect keylog) (default: 1518)
      --capture-buffer-size int        number of packets to buffer (will start flushing packets before
                                       --capture-buffer-delay when this gets half full) (default: automatic) (does not
                                       affect keylog)
```

#### Simple one-off sslkeylog to stdout

```bash
adb shell su -c '/data/local/tmp/asslcapture --scan --capture keylog'
```

#### Saving a pcapng file

```bash
adb shell su -c '/data/local/tmp/asslcapture --exit-eof --scan --capture pcapng --output /data/local/tmp/capture.pcapng'
# press ctrl+d to end gracefully
```

#### Piping it directly into wireshark

```
adb shell su -c '/data/local/tmp/asslcapture --cache /data/local/tmp/asslcapture.cache --scan --capture pcapng | wireshark -k -i -
```

#### Piping it directly into wireshark with a default display filter for HTTP/GRPC

```bash
adb shell su -c '/data/local/tmp/asslcapture --cache /data/local/tmp/asslcapture.cache --scan --capture pcapng -f "tcp port 443 or udp port 443"' |
wireshark -k -i - -Y 'http.request.full_uri or http2.request.full_uri or http3.request.full_uri or grpc
```

#### Useful tools

- [Wireshark](https://www.wireshark.org/) has the best protocol support, but is a little bit tedious to use for looking at HTTP traffic.
- [editcap](https://www.wireshark.org/docs/man-pages/editcap.html) can merge a sslkeylog file into a pcap (`--inject-secrets`) or extract them from a pcapng (`--extract-secrets`).
- [pcapng_to_har](https://github.com/PiRogueToolSuite/pcapng-utils) converts HTTP1.1 and HTTP/2 traffic to a HAR for easier inspection
