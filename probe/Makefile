.PHONY: build build-all clean test

BINARY := ast-probe
VERSION := 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := CGO_ENABLED=0

# Default: build for current platform
build:
	$(GOFLAGS) go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

# Cross-compile static binaries for all targets
build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64

build-linux-amd64:
	$(GOFLAGS) GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64 .

build-linux-arm64:
	$(GOFLAGS) GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-arm64 .

build-darwin-amd64:
	$(GOFLAGS) GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-amd64 .

build-darwin-arm64:
	$(GOFLAGS) GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-arm64 .

test:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY)-linux-* $(BINARY)-darwin-*
