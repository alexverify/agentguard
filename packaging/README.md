# packaging/ — distribution (seam)

Release and distribution tooling: the GoReleaser config, the Homebrew cask, and `install.sh`. `make build` still produces a local binary directly.

## Outputs (GoReleaser)

- GitHub Releases with signed checksums (macOS/Linux/Windows, amd64/arm64).
- A Homebrew tap (`brew install alexverify/tap/eyebrow`) via the `homebrew_casks:` block.
- `install.sh` (`curl | sh`) — checksum-verified binary download.

npm distribution was considered and **declined**: shipping a Go binary through
npm needs a package-per-platform fan-out (scope, publish token, N packages) and
is not the idiomatic Go path. See
`docs/superpowers/specs/2026-06-20-distribution-design.md`.

## Trust model (unsigned by choice)

Release binaries are **not** Apple-signed or notarized — that requires a paid
Apple Developer Program account, which this project deliberately avoids. The
Homebrew cask strips the macOS quarantine xattr post-install so the CLI runs.

What you get instead, all free and verifiable:

- **Checksums** — `checksums.txt` on every release; `install.sh` verifies
  automatically, manual downloads via `shasum -a 256 -c`.
- **Build provenance** — every release artifact is attested with GitHub's
  build-provenance attestation. `gh attestation verify <archive>
  -R alexverify/eyebrow` proves the file was built by this repo's release
  workflow from a specific commit.
- **Build from source** — `go install github.com/alexverify/eyebrow/cmd/eyebrow@latest`
  or `git clone` + `make install`; requires only Go 1.25+. For anyone unwilling
  to run a prebuilt binary, compiling locally is the trust path.
