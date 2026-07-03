# signet build.
#
# On macOS the Secure Enclave backend is a CryptoKit (Swift) shim compiled to a
# static archive and linked into the one Go binary via cgo. The Swift runtime
# ships with macOS, so the binary stays self-contained (no sidecar, no helper).
# On Linux/Windows there is no Swift step (enclave_darwin.go is darwin-only) and
# `go build` alone is sufficient.
#
# Plain `go build` on macOS will fail to link unless internal/signer/libsignet_se.a
# exists, so always build the Mac binary with `make build` (or run the swift step
# first).

GO ?= go
BINARY ?= signet
SWIFT_SRC := internal/signer/enclave.swift
SWIFT_OBJ := internal/signer/enclave.o
SWIFT_LIB := internal/signer/libsignet_se.a

VERSION := $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

UNAME_S := $(shell uname -s)

.PHONY: build test clean

ifeq ($(UNAME_S),Darwin)

build: $(SWIFT_LIB)
	CGO_ENABLED=1 $(GO) build $(LDFLAGS) -o $(BINARY) ./cmd/signet

test: $(SWIFT_LIB)
	CGO_ENABLED=1 $(GO) test ./...

$(SWIFT_LIB): $(SWIFT_SRC)
	xcrun swiftc -O -emit-object -parse-as-library $(SWIFT_SRC) -o $(SWIFT_OBJ)
	ar rcs $(SWIFT_LIB) $(SWIFT_OBJ)

else

build:
	CGO_ENABLED=1 $(GO) build $(LDFLAGS) -o $(BINARY) ./cmd/signet

test:
	CGO_ENABLED=1 $(GO) test ./...

endif

clean:
	rm -f $(BINARY) $(SWIFT_OBJ) $(SWIFT_LIB)
