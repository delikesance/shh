export GOPATH := $(HOME)/go

BINARY_NAME=shh
BUILD_DIR=bin

.PHONY: all build run clean test

all: build

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/shh

run:
	go run ./cmd/shh -p 2222

test:
	go test -v -race ./...

clean:
	rm -rf $(BUILD_DIR)
