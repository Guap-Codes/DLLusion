// src/injector/main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdll                  = windows.NewLazyDLL("ntdll.dll")
	ntAllocateVirtualMemory = ntdll.NewProc("NtAllocateVirtualMemory")
	ntWriteVirtualMemory    = ntdll.NewProc("NtWriteVirtualMemory")
	ntCreateThreadEx       = ntdll.NewProc("NtCreateThreadEx")
)

func main() {
	var pid int
	var dllPath string

	flag.IntVar(&pid, "pid", 0, "Process ID to inject into")
	flag.StringVar(&dllPath, "dll", "", "Path to the DLL file")
	flag.Parse()

	if pid == 0 || dllPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Open target process
	processHandle, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		log.Fatal("OpenProcess failed:", err)
	}
	defer windows.CloseHandle(processHandle)

	// Convert DLL path to UTF-16
	dllPathUTF16, err := windows.UTF16FromString(dllPath)
	if err != nil {
		log.Fatal("UTF16 conversion failed:", err)
	}
	dllPathBytes := make([]byte, len(dllPathUTF16)*2)
	for i, c := range dllPathUTF16 {
		dllPathBytes[i*2] = byte(c)
		dllPathBytes[i*2+1] = byte(c >> 8)
	}

	// Allocate memory in remote process
	var baseAddr uintptr
	regionSize := uintptr(len(dllPathBytes))
	ret, _, _ := ntAllocateVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&baseAddr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if ret != 0 {
		log.Fatal("NtAllocateVirtualMemory failed:", ret)
	}

	// Write DLL path to remote memory
	var bytesWritten uintptr
	ret, _, _ = ntWriteVirtualMemory.Call(
		uintptr(processHandle),
		baseAddr,
		uintptr(unsafe.Pointer(&dllPathBytes[0])),
		uintptr(len(dllPathBytes)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret != 0 {
		log.Fatal("NtWriteVirtualMemory failed:", ret)
	}

	// Get LoadLibraryW address
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	loadLibraryW := kernel32.NewProc("LoadLibraryW")

	// Create remote thread
	var threadHandle uintptr
	ret, _, _ = ntCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		uintptr(0x1FFFFF), // THREAD_ALL_ACCESS
		0,
		uintptr(processHandle),
		loadLibraryW.Addr(),
		baseAddr,
		0,
		0,
		0,
		0,
		0,
	)
	if ret != 0 {
		log.Fatal("NtCreateThreadEx failed:", ret)
	}
	defer windows.CloseHandle(windows.Handle(threadHandle))

	windows.WaitForSingleObject(windows.Handle(threadHandle), windows.INFINITE)
	fmt.Println("Injection successful")
}