# Makefile for Bombdrop mDNS Cache Pressure Tool

# Binary name
BINARY_NAME=bombdrop

# Version info
VERSION=1.0.0
BUILD_TIME=$(shell date +%FT%T%z)
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOGET=$(GOCMD) get
GOFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

# Build directories
BUILD_DIR=bin
LINUX_DIR=$(BUILD_DIR)/linux
MACOS_DIR=$(BUILD_DIR)/macos
WINDOWS_DIR=$(BUILD_DIR)/windows

# Platforms to build for
#PLATFORMS=linux-amd64 linux-arm64 macos-amd64 macos-arm64 windows-amd64 windows-arm64
PLATFORMS=macos-arm64

# Default target
.PHONY: all
all: clean build

# Build all platforms
.PHONY: build
build: $(PLATFORMS)

# Clean build directory
.PHONY: clean
clean:
	@echo "Cleaning build directory..."
	@rm -rf $(BUILD_DIR)
	@mkdir -p $(LINUX_DIR) $(MACOS_DIR) $(WINDOWS_DIR)

# Initialize and tidy Go modules
.PHONY: init
init:
	$(GOMOD) tidy

# Run tests
.PHONY: test
test:
	$(GOTEST) -v ./...

# Build for Linux AMD64
.PHONY: linux-amd64
linux-amd64:
	@echo "Building for Linux (AMD64)..."
	@GOOS=linux GOARCH=amd64 $(GOBUILD) $(GOFLAGS) -o $(LINUX_DIR)/$(BINARY_NAME)-linux-amd64 .

# Build for Linux ARM64
.PHONY: linux-arm64
linux-arm64:
	@echo "Building for Linux (ARM64)..."
	@GOOS=linux GOARCH=arm64 $(GOBUILD) $(GOFLAGS) -o $(LINUX_DIR)/$(BINARY_NAME)-linux-arm64 .

# Build for macOS AMD64
.PHONY: macos-amd64
macos-amd64:
	@echo "Building for macOS (AMD64)..."
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) $(GOFLAGS) -o $(MACOS_DIR)/$(BINARY_NAME)-macos-amd64 .

# Build for macOS ARM64
.PHONY: macos-arm64
macos-arm64:
	@echo "Building for macOS (ARM64)..."
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) $(GOFLAGS) -o $(MACOS_DIR)/$(BINARY_NAME)-macos-arm64 .

# Build for Windows AMD64
.PHONY: windows-amd64
windows-amd64:
	@echo "Building for Windows (AMD64)..."
	@GOOS=windows GOARCH=amd64 $(GOBUILD) $(GOFLAGS) -o $(WINDOWS_DIR)/$(BINARY_NAME)-windows-amd64.exe .

# Build for Windows ARM64
.PHONY: windows-arm64
windows-arm64:
	@echo "Building for Windows (ARM64)..."
	@GOOS=windows GOARCH=arm64 $(GOBUILD) $(GOFLAGS) -o $(WINDOWS_DIR)/$(BINARY_NAME)-windows-arm64.exe .

# Create release archives
.PHONY: release
release: build
	@echo "Creating release archives..."
	@cd $(LINUX_DIR) && tar -czf ../$(BINARY_NAME)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64
	@cd $(LINUX_DIR) && tar -czf ../$(BINARY_NAME)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64
	@cd $(MACOS_DIR) && tar -czf ../$(BINARY_NAME)-macos-amd64.tar.gz $(BINARY_NAME)-macos-amd64
	@cd $(MACOS_DIR) && tar -czf ../$(BINARY_NAME)-macos-arm64.tar.gz $(BINARY_NAME)-macos-arm64
	@cd $(WINDOWS_DIR) && zip -q ../$(BINARY_NAME)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe
	@cd $(WINDOWS_DIR) && zip -q ../$(BINARY_NAME)-windows-arm64.zip $(BINARY_NAME)-windows-arm64.exe
	@echo "Release archives created in $(BUILD_DIR) directory"

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	$(GOGET) -v ./...

# Help target
.PHONY: help
help:
	@echo "Bombdrop Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make              Build for all platforms"
	@echo "  make clean        Clean build directory"
	@echo "  make init         Initialize and tidy Go modules"
	@echo "  make test         Run tests"
	@echo "  make linux-amd64  Build for Linux AMD64"
	@echo "  make linux-arm64  Build for Linux ARM64"
	@echo "  make macos-amd64  Build for macOS AMD64"
	@echo "  make macos-arm64  Build for macOS ARM64"
	@echo "  make windows-amd64 Build for Windows AMD64"
	@echo "  make windows-arm64 Build for Windows ARM64"
	@echo "  make release      Create release archives"
	@echo "  make deps         Install dependencies"
	@echo "  make help         Show this help message"
