# secrt

Share digital secrets from the command line.

End-to-end encrypted secret sharing using X25519-XSalsa20-Poly1305 public-key authenticated encryption.

## Quick Start

```sh
# Enrol with your email
secrt enrol me@example.com

# Invite a peer
secrt invite friend@example.com

# Send a secret
echo "p4ssw0rd" | secrt send friend@example.com

# List your inbox
secrt ls

# Download and decrypt
secrt get cbf061e6 > secret.txt
```

## Install

Download the latest binary from [GitHub Releases](https://github.com/commandquery/secrt/releases/latest):

**macOS**
```sh
# Apple Silicon
curl -L https://github.com/commandquery/secrt/releases/latest/download/secrt-darwin-arm64 -o secrt && chmod +x secrt

# Intel
curl -L https://github.com/commandquery/secrt/releases/latest/download/secrt-darwin-amd64 -o secrt && chmod +x secrt
```

**Linux**
```sh
# x86_64
curl -L https://github.com/commandquery/secrt/releases/latest/download/secrt-linux-amd64 -o secrt && chmod +x secrt

# ARM64
curl -L https://github.com/commandquery/secrt/releases/latest/download/secrt-linux-arm64 -o secrt && chmod +x secrt
```

**Windows (PowerShell)**
```powershell
Invoke-WebRequest -Uri "https://github.com/commandquery/secrt/releases/latest/download/secrt-windows-amd64.exe" -OutFile "secrt.exe"
```

## License

Apache-2.0
