// src/controller/winapi_wrapper.go
//go:build windows
// +build windows
package main

import "golang.org/x/sys/windows"

// Wraps Windows APIs for cross-platform compatibility
func RemoteExecute(dllName string, funcName string, args ...uintptr) uintptr {
    dll := windows.NewLazyDLL(dllName)
    proc := dll.NewProc(funcName)
    ret, _, _ := proc.Call(args...)
    return ret
}