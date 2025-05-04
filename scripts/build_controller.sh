#!/bin/bash
cd ../src/controller/

# Build Linux controller
echo "Building Linux controller..."
GOOS=linux GOARCH=amd64 go build -tags "!windows" -ldflags="-s -w" -o ../../build/linux/controller

# Build Windows controller
echo "Building Windows controller..."
GOOS=windows GOARCH=amd64 go build -tags "windows" -ldflags="-s -w -H=windowsgui" -o ../../build/windows/controller.exe

echo "Build complete. Outputs:"
ls -lh ../../build/{linux,windows}/