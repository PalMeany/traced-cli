BINARY  := traced
PKG     := github.com/PalMeany/traced-cli
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(PKG)/internal/app.Version=$(VERSION)
PREFIX  ?= $(shell go env GOPATH)/bin

.PHONY: build install test vet fmt clean run cross sums

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/traced

install: build
	install -d $(PREFIX)
	install -m 0755 $(BINARY) $(PREFIX)/$(BINARY)
	@echo "installed $(PREFIX)/$(BINARY)"

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

cross:
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-amd64 ./cmd/traced
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-arm64 ./cmd/traced
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-darwin-arm64 ./cmd/traced
	GOOS=linux  GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-arm ./cmd/traced
	GOOS=linux  GOARCH=386 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-386 ./cmd/traced
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-freebsd-amd64 ./cmd/traced
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-darwin-amd64 ./cmd/traced

sums: cross
	cd dist && (sha256sum traced-* 2>/dev/null || shasum -a 256 traced-*) > SHA256SUMS

clean:
	rm -rf $(BINARY) dist
