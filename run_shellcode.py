#!/usr/bin/python3

import sys
from pwn import *

def execute_shellcode(shellcode_hex):
    try:
        context(os="linux", arch="amd64", log_level="error")

        if not shellcode_hex:
            raise ValueError("Shellcode is empty or invalid.")

        shellcode_bytes = unhex(shellcode_hex)

        p = run_shellcode(shellcode_bytes)
        p.interactive()

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./run_shellcode.py <shellcode_hex>")
        sys.exit(1)

    shellcode_hex = sys.argv[1]
    execute_shellcode(shellcode_hex)
