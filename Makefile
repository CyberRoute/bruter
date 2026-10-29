NAME=bruter
SOURCE=cmd/$(NAME)/*.go

# golangci-lint is pinned so local `make lint` matches CI. If it is not already
# on PATH, the lint target bootstraps this version into ./bin via `go install`.
GOLANGCI_LINT_VERSION ?= v2.15.0
BIN := $(CURDIR)/bin
GOLANGCI_LINT := $(BIN)/golangci-lint

all: clean ui test lint fmt
	@echo "Building..."
	@mkdir -p build
	go build -o build/$(NAME) $(SOURCE)

# Build the React UI (web/dist) that is embedded into the Go binary via
# go:embed. Run this before any go build/test/lint.
ui:
	@echo "Building web UI..."
	npm --prefix web ci
	npm --prefix web run build

test: ui
	@echo "Running tests..."
	go test ./... -v -cover -race

lint:
	@echo "Running lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	elif [ -x "$(GOLANGCI_LINT)" ]; then \
		"$(GOLANGCI_LINT)" run; \
	else \
		echo "golangci-lint not found; installing $(GOLANGCI_LINT_VERSION) into $(BIN)..."; \
		GOBIN="$(BIN)" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
		"$(GOLANGCI_LINT)" run; \
	fi

fmt:
	@echo "Formatting..."
	gofmt -s -w .

clean:
	@echo "Cleaning up"
	rm -rf build web/dist
