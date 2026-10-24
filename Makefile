BINARY = pcmd
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

# Note: release builds are produced by GoReleaser (see .goreleaser.yaml), which
# injects the real version/commit/date from the git tag. These targets are for
# local/dev builds and CI smoke checks.
# Pinned so local runs and CI (see .github/workflows/ci.yml) agree.
STATICCHECK = honnef.co/go/tools/cmd/staticcheck@v0.8.2

.PHONY: build test lint e2e test-docker clean all

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/pcmd

test:
	go test ./... -v -timeout 60s

# gofmt must report nothing, then vet and staticcheck must be clean.
lint:
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "gofmt: $$unformatted"; exit 1; fi
	go vet ./...
	go run $(STATICCHECK) ./...

# The in-process end-to-end suite against a throwaway HOME (it pairs
# devices, writes config.json, audit.log and ~/.ssh under it).
e2e:
	HOME="$$(mktemp -d)" go run ./cmd/e2e-test

test-docker:
	bash docker/test.sh

clean:
	rm -f $(BINARY) $(BINARY)-* e2e-test

all: pcmd-darwin-amd64 pcmd-darwin-arm64 pcmd-linux-amd64 pcmd-linux-arm64

pcmd-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/pcmd

pcmd-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/pcmd

pcmd-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/pcmd

pcmd-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/pcmd
