#!/usr/bin/python3

import sys
import os
from pwn import *

def extract_shellcode(binary_path):
    try:
        context(os="linux", arch="amd64", log_level="error")

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"File not found: {binary_path}")

        file = ELF(binary_path)
        
        shellcode = file.section(".text")
        
        if any(byte == 0 for byte in shellcode):
            print("%d bytes - Found NULL byte" % len(shellcode))
        else:
            print("%d bytes - No NULL bytes" % len(shellcode))
        
        return shellcode.hex()
        
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./shellcode.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    extracted_shellcode = extract_shellcode(binary_path)
    
    if isinstance(extracted_shellcode, str):
        print(extracted_shellcode)
    else:
        print("Error:", extracted_shellcode)

