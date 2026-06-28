.PHONY: build test lint run clean docker docker-compose install install-tools check-deps

BINARY := redhands
BUILD_DIR := bin
IMAGE := redhands
INSTALL_DIR := /usr/local/bin
PROFILE := minimal

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

install: build
	install -m 755 $(BUILD_DIR)/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo ""
	@echo "RedHands installed to $(INSTALL_DIR)/$(BINARY)"
	@echo "Run 'make check-deps' to verify tool availability."

install-tools:
	@chmod +x scripts/install-tools.sh
	sudo scripts/install-tools.sh --profile $(PROFILE)

check-deps:
	@chmod +x scripts/check-deps.sh
	@scripts/check-deps.sh
