## Building

To build the main binary from a local clone:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -v .
```

To build the test SSL client:

```bash
cd scripts
javac --release 8 SSLClient.java
/path/to/android/build-tools/version/d8 --output . --min-api 21 SSLClient.class
# the output is in classes.dex
```

To regenerate the probe bpf if you modified the `.c` files:

```bash
export ANDROID_HOME=/path/to/android # option 1
export ANDROID_NDK_HOME=/path/to/android/ndk/25.1.8937393 # option 2
go generate ./internal/probe
```

To test the analysis on a library:

```bash
go run ./internal/analyze/main.go libssl.so
```

For development in vscode, you'll probably want this in your workspace settings:

```json
{
    "go.toolsEnvVars": {
        "GOOS": "linux",
        "GOARCH": "arm64"
    }
}
```
