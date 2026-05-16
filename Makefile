BINARY  := doppel
PKG     := ./cmd/doppel
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build install test vet fmt lint tidy check clean

## build: compile the doppel binary with the version stamped in
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## install: install doppel into GOBIN
install:
	go install -ldflags "$(LDFLAGS)" $(PKG)

## test: run the test suite with the race detector
test:
	go test -race -count=1 ./...

## vet: run go vet
vet:
	go vet ./...

## fmt: format all Go files
fmt:
	gofmt -w .

## lint: fail if any Go file is not gofmt-formatted
lint:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-formatted:"; echo "$$unformatted"; exit 1; \
	fi

## tidy: tidy the module graph
tidy:
	go mod tidy

## check: build, vet, lint and test
check: build vet lint test

## clean: remove build artifacts
clean:
	rm -f $(BINARY) $(BINARY).exe
