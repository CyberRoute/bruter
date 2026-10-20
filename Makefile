NAME=bruter
SOURCE=cmd/$(NAME)/*.go

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
	go list ./... | golangci-lint run

fmt:
	@echo "Formatting..."
	gofmt -s -w .

clean:
	@echo "Cleaning up"
	rm -rf build web/dist
