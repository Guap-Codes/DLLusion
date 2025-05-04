#!/bin/bash
cd ../src/injector/

# Build with static linking
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ../../build/windows/injector.exe

# Verify build
if [ $? -eq 0 ]; then
    echo "[+] EXE built successfully"
    file ../../build/windows/injector.exe
else
    echo "[!] EXE build failed"
    exit 1
fi

