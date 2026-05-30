## Troubleshooting

### General troubleshooting

#### Analysis failures

- If the library isn't being scanned at all, pass it to `--scan-lib`.

- Try clearing the cache (or not using it at all) and re-scanning.

- Try running `go run ./internal/analyze/main.go libssl.so` (pulling the library and using it instead of `libssl.so`), and see what it says.

- If you know how, open the library in a disassembler and attempt to find the offsets manually (see the comments in internal/analyze).

- Open an issue.

#### Probe attach failures

- Ensure your are running as root and/or have the required capabilities.

- Check dmesg for AVC denials to ensure you aren't getting blocked by selinux.

- Check your kernel version.
  - 4.1 is the absolute minimum unless you use `--probe-ptrace`.
  - 4.14 is the lowest that's likely to work at all, but requires `--probe-noread` if it doesn't have the fixes for `bpf_probe_read_from_user` on ARM64 backported. Alternatively, you can use `--probe-ptrace`.
  - 5.15+ should generally work fine.

- Check whether at least one of the following paths exist. If not, try mounting debugfs.
  - `/sys/bus/event_source/devices/uprobe/type`
  - `/sys/kernel/tracing`
  - `/sys/kernel/debug/tracing`

- Check /proc/config.gz. If you don't have these, you probably won't be able to use this tool unless you use `--probe-ptrace`.
  - `CONFIG_BPF_SYSCALL=y`
  - `CONFIG_BPF_EVENTS=y`
  - `CONFIG_PERF_EVENTS=y`
  - `CONFIG_UPROBES=y`
  - `CONFIG_UPROBE_EVENTS=y`

- Open an issue with the error message, your device, and your kernel version.

#### Decryption not working

- Try reconnecting to the network and/or restarting the app to ensure a new TLS connection is established.

- Ensure the connection happens after the corresponding probe is attached (see the logs).

- Ensure the SSL library used by the process is in the list.

- Check for dropped probe events.

- If using `--probe-noread`, there's probably not much you can do about it. If you have specific PIDs, you can try `--probe-ptrace`.

- Check the list of issues below.

- Try the sample SSL client in `scripts/SSLClient.java`.

### Common issues

- **scan takes too long** \
  Use `--cache` if you aren't using it already.

- **analysis failures with incorrect ssl_log_secret offset** \
  Try using `--ignore-dbginfo`. You'll need to clear the cache if you're using it. If it still doesn't work, open an issue and attach the library.

- **missing secrets with no other log messages about drops or errors** \
  Look at `/proc/{pid}/maps` for more information about the loaded libraries, then use `--scan-lib` with the full path to ensure the library was analyzed.

- **probe attach errors mentioning the verifier, or probes failing with error -14** \
  Try `--probe-noread` (but note that this option is flaky). If it still doesn't work, open an issue and mention your device and kernel version.

- **"dropped keylog events"** \
  Increase the `--probe-buffer` option.

- **"dropped packets"** \
  Verify that `--capture-buffer-pktsize` is larger than your MTU, then try increasing `--capture-buffer-size`. Also ensure your output is fast enough to keep up.

- **decryption secret blocks in the pcapng output are out of order** \
  Increase `--capture-buffer-delay`.

- **infinite traffic in pcapng mode with adb over wifi** \
  Add a capture filter to exclude the ADB traffic.

- **duplicate secrets emitted** \
  This may happen if libraries are symlinked or hardlinked, and shouldn't cause any other issues.

- **process crashes after capture is stopped when using `--probe-ptrace`** \
  When using ptrace, you must exit cleanly (send a interrupt, or close stdin with `--exit-eof`) otherwise breakpoints will be left in the process.

- **missing secrets when using `--probe-ptrace`** \
  When using ptrace, the library must be loaded at the time it is attached. If not loaded, nothing will happen (and currently, no warning will be printed either). Libraries loaded later on will not currently be detected automatically (this may be implemented in the future).

### Library locations

On Android, BoringSSL is usually wrapped with conscrypt (for usage from Java), which may come from:

- Loadable GMS module (before Android 4.1).
- The system conscrypt (before Android 10).
- Mainline conscrypt APEX (Android 10+).
- Apps (via `org.conscrypt:conscrypt-android`).

Some apps use BoringSSL natively by statically linking it, including:

- Chromium/Chrome.
- Google Apps.
- Other apps (via `org.chromium.net:cronet-embedded`).

If BoringSSL cannot be detected, keys will not be logged for connections from that application.
