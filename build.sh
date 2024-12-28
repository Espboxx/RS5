#!/bin/bash

# Exit on error
set -e

# Create output directory
mkdir -p build

# Build flags
FLAGS="-ldflags=-s -w"

# Windows builds
GOOS=windows
CGO_ENABLED=0

for GOARCH in amd64 386 arm64; do
    echo "Building for Windows ${GOARCH}..."
    go build ${FLAGS} -o "build/reverseproxy_windows_${GOARCH}.exe"
done

# Linux builds
GOOS=linux

for GOARCH in amd64 386 arm64; do
    echo "Building for Linux ${GOARCH}..."
    go build ${FLAGS} -o "build/reverseproxy_linux_${GOARCH}"
done

# macOS builds
GOOS=darwin

for GOARCH in amd64 arm64; do
    echo "Building for macOS ${GOARCH}..."
    go build ${FLAGS} -o "build/reverseproxy_darwin_${GOARCH}"
done

echo "Build completed successfully" 