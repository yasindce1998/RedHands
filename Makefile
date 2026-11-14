.PHONY: build test test-live test-e2e lint run clean docker docker-compose install install-tools check-deps

BINARY := redhands
BUILD_DIR := bin
IMAGE := redhands
INSTALL_DIR := /usr/local/bin
PROFILE := minimal

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/redhands
	go build -o $(BUILD_DIR)/redhands-cli ./cmd/redhands-cli
	go build -o $(BUILD_DIR)/redhands-creds ./cmd/redhands-creds

test:
	go test -race -cover ./...

test-live:
	go test -tags=livebin ./tools/livecheck/... -run TestLiveFlagSurface -v

test-e2e:
	go test -tags=livee2e ./tools/e2e/... -v

lint:
	golangci-lint run ./...

run: build
	$(BUILD_DIR)/$(BINARY)

clean:
	rm -rf $(BUILD_DIR)

docker:
	docker build -t $(IMAGE) .

docker-compose:
	docker compose run --build --rm -i redhands

install: build
	install -m 755 $(BUILD_DIR)/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	install -m 755 $(BUILD_DIR)/redhands-cli $(INSTALL_DIR)/redhands-cli
	install -m 755 $(BUILD_DIR)/redhands-creds $(INSTALL_DIR)/redhands-creds
	@echo ""
	@echo "RedHands installed to $(INSTALL_DIR)/$(BINARY)"
	@echo "Run 'make check-deps' to verify tool availability."

install-tools:
	@chmod +x scripts/install-tools.sh
	sudo scripts/install-tools.sh --profile $(PROFILE)

check-deps:
	@chmod +x scripts/check-deps.sh
	@scripts/check-deps.sh
