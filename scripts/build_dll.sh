#!/bin/bash
cd ../src/dll/

# Build Windows DLL with CGO cross-compilation
CGO_ENABLED=1 \
GOOS=windows \
GOARCH=amd64 \
CC=x86_64-w64-mingw32-gcc \
go build -buildmode=c-shared \
    -ldflags="-s -w" \
    -o ../../build/windows/injected.dll

# Verify build
if [ $? -eq 0 ]; then
    echo "[+] DLL built successfully"
    file ../../build/windows/injected.dll
else
    echo "[!] DLL build failed"
    exit 1
fi

# // Second Command
# GOOS=windows GOARCH=amd64 go build -buildmode=c-shared -ldflags="-s -w" -o ../../build/injected.dll