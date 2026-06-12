.PHONY: test verify format-check lint vet staticcheck golangci-lint bash-tests powershell-checks build build-go release release-go bundle clean

GO ?= go
GOFMT ?= gofmt
BASH ?= bash
SHFMT ?= shfmt
STATICCHECK ?= staticcheck
GOLANGCI_LINT ?= golangci-lint
OUTPUT_DIR ?= dist
BINARY_NAME ?= intruder-hunter
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION_PACKAGE := github.com/creativeprofit22/intruder-hunter/internal/version
LDFLAGS ?= -s -w -X $(VERSION_PACKAGE).Version=$(VERSION) -X $(VERSION_PACKAGE).Commit=$(COMMIT)
HOST_OS := $(shell $(GO) env GOOS)
HOST_ARCH := $(shell $(GO) env GOARCH)
GO_PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

staticcheck:
	@if command -v $(STATICCHECK) >/dev/null 2>&1; then \
		$(STATICCHECK) ./...; \
	else \
		echo "SKIP staticcheck ./...: $(STATICCHECK) is not installed"; \
	fi

golangci-lint:
	@if ! command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then \
		echo "SKIP golangci-lint run ./...: $(GOLANGCI_LINT) is not installed"; \
	else \
		module_version=$$(awk '$$1 == "go" { print $$2; exit }' go.mod); \
		module_minor=$$(printf '%s\n' "$$module_version" | awk -F. '{ print $$2 }'); \
		built_version=$$($(GOLANGCI_LINT) version 2>/dev/null | sed -n 's/.*built with \(go[0-9][0-9]*\.[0-9][0-9]*\(\.[0-9][0-9]*\)*\).*/\1/p'); \
		built_minor=$$(printf '%s\n' "$${built_version#go}" | awk -F. '{ print $$2 }'); \
		if [ -n "$$module_minor" ] && [ -n "$$built_minor" ] && [ "$$built_minor" -lt "$$module_minor" ]; then \
			echo "SKIP golangci-lint run ./...: $(GOLANGCI_LINT) was built with $$built_version, which is older than module go $$module_version"; \
		else \
			$(GOLANGCI_LINT) run ./...; \
		fi; \
	fi

lint:
	$(BASH) scripts/verify.sh --lint-only

verify:
	$(BASH) scripts/verify.sh

bash-tests:
	$(BASH) scripts/verify.sh --bash-tests-only

powershell-checks:
	$(BASH) scripts/verify.sh --powershell-only

format-check:
	@status=0; \
	if command -v $(GOFMT) >/dev/null 2>&1; then \
		unformatted="$$($(GOFMT) -l .)"; \
		if [ -n "$$unformatted" ]; then \
			printf '%s\n' "$$unformatted"; \
			echo "FAIL gofmt -l ."; \
			status=1; \
		else \
			echo "PASS gofmt -l ."; \
		fi; \
	else \
		echo "SKIP gofmt -l .: $(GOFMT) is not installed"; \
	fi; \
	if command -v $(SHFMT) >/dev/null 2>&1; then \
		if $(SHFMT) -d -i 4 -ln bash intruder-hunter.sh intruder-hunter-macos.sh lib/linux/*.sh lib/macos/*.sh scripts/*.sh; then \
			echo "PASS shfmt -d -i 4 -ln bash"; \
		else \
			echo "FAIL shfmt -d -i 4 -ln bash"; \
			status=1; \
		fi; \
	else \
		echo "SKIP shfmt -d -i 4 -ln bash: $(SHFMT) is not installed"; \
	fi; \
	exit $$status

build: build-go

build-go:
	mkdir -p $(OUTPUT_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-$(HOST_OS)-$(HOST_ARCH) ./cmd/intruder-hunter

release: bundle release-go

release-go:
	GO="$(GO)" $(BASH) scripts/release-go.sh

bundle:
	$(BASH) scripts/bundle.sh

clean:
	rm -rf $(OUTPUT_DIR)
