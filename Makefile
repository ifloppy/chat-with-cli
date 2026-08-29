VERSION ?= $(shell sed -n '1p' VERSION)
LDFLAGS ?= -X github.com/ifloppy/chat-with-cli/internal/version.Value=$(VERSION)

.PHONY: build test check version

build:
	go build -ldflags "$(LDFLAGS)" -o chat-with-cli ./cmd/chat-with-cli

test:
	go test ./...

check: test
	go vet ./...
	git diff --check

version:
	@printf '%s\n' "$(VERSION)"
