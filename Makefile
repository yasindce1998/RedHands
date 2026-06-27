.PHONY: build test lint run clean docker docker-compose

BINARY := redhands
BUILD_DIR := bin
IMAGE := redhands

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

docker:
	docker build -t $(IMAGE) .

docker-compose:
	docker compose up --build
