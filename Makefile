NAME=bruter
SOURCE=cmd/$(NAME)/*.go

all: clean test lint fmt
	@echo "Building..."
	@mkdir -p build
	go build -o build/$(NAME) $(SOURCE)

test:
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
	rm -rf build
