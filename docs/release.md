# Local version and release workflow

This project is intentionally kept unreleased while the public Relay and
client experience are being developed. Version state is still explicit and
reproducible:

1. `VERSION` is the human-maintained candidate version.
2. `internal/version/version.go` contains the same safe fallback for source
   builds and is overridden by the linker for packaged builds.
3. `mcpserver.Version`, CLI `version`, MCP client metadata, and Relay pages all
   read the shared value.
4. `make build VERSION=0.1.0-alpha.6` stamps a local candidate without
   changing source. `make check` runs tests, vet, and whitespace checks.

Before a future release, update `VERSION`, update the fallback in
`internal/version/version.go`, add a dated entry to the changelog, run
`make check`, and create a signed/tagged commit. Do not publish a release or
enable an installer channel until the release artifacts and `SHA256SUMS` have
been built and reviewed.

The workstation installer and `update` command are review-first. They only
change a local binary after an explicit apply flag and preserve a verified
`.previous` rollback copy.
