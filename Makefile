.PHONY: build test lint run clean

BINARY := redhands
BUILD_DIR := bin

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/redhands

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

run: build
	$(BUILD_DIR)/$(BINARY)

clean:
	rm -rf $(BUILD_DIR)
