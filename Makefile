.PHONY: help build test lint e2e e2e-release fmt clean

UNAME_S := $(shell uname -s)

help:
	@echo "Available targets:"
	@echo "  make build  - Build the project"
	@echo "  make test   - Run tests (no llzk-interpreter e2e group)"
	@echo "  make e2e    - Run ACIR→LLZK→interpreter e2e tests (--features e2e)"
	@echo "  make e2e-release - Run ACIR→LLZK→interpreter e2e tests in release mode"
	@echo "  make lint   - Run clippy"
	@echo "  make fmt    - Run rustfmt"
	@echo "  make clean  - Remove build artifacts"

build:
ifeq ($(UNAME_S),Darwin)
	./scripts/build-macos.sh build
else
	cargo build
endif

test:
ifeq ($(UNAME_S),Darwin)
	./scripts/build-macos.sh test
else
	cargo test
endif

e2e:
ifeq ($(UNAME_S),Darwin)
	./scripts/build-macos.sh test -p acir2llzk --features e2e -- tests::e2e
else
	cargo test -p acir2llzk --features e2e -- tests::e2e
endif

e2e-release:
ifeq ($(UNAME_S),Darwin)
	./scripts/build-macos.sh test --release -p acir2llzk --features e2e -- tests::e2e
else
	cargo test --release -p acir2llzk --features e2e -- tests::e2e
endif

lint:
ifeq ($(UNAME_S),Darwin)
	./scripts/build-macos.sh clippy -p acir2llzk --all-targets --all-features -- -D warnings
else
	cargo clippy -p acir2llzk --all-targets --all-features -- -D warnings
endif

fmt:
ifeq ($(UNAME_S),Darwin)
	./scripts/build-macos.sh fmt --all
else
	cargo fmt --all
endif

clean:
	cargo clean
