#!/usr/bin/python3

import sys
import os
import stat
from pwn import *

def create_executable(shellcode_hex, output_filename):
    try:
        context(os="linux", arch="amd64", log_level="error")

        if not shellcode_hex:
            raise ValueError("Shellcode is empty or invalid.")
        if not output_filename:
            raise ValueError("Output filename is empty or invalid.")

        shellcode_bytes = unhex(shellcode_hex)

        elf = ELF.from_bytes(shellcode_bytes)
        elf.save(output_filename)

        os.chmod(output_filename, stat.S_IEXEC)

        print(f"Executable saved as {output_filename}")

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./create_executable.py <shellcode_hex> <output_filename>")
        sys.exit(1)

    shellcode_hex = sys.argv[1]
    output_filename = sys.argv[2]

    create_executable(shellcode_hex, output_filename)
