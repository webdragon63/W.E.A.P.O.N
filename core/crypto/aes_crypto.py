import argparse
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import os

BLOCK_SIZE = 16
SALT_SIZE = 16
KEY_LEN = 32

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    return data[:-data[-1]]

def encrypt(data, password):
    salt = os.urandom(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_LEN)
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data))
    return base64.b64encode(salt + iv + ciphertext).decode()

def decrypt(enc_data, password):
    raw = base64.b64decode(enc_data)
    salt = raw[:SALT_SIZE]
    iv = raw[SALT_SIZE:SALT_SIZE+BLOCK_SIZE]
    ciphertext = raw[SALT_SIZE+BLOCK_SIZE:]
    key = PBKDF2(password, salt, dkLen=KEY_LEN)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext))

def main():
    parser = argparse.ArgumentParser(description="AES-256-CBC Encrypt/Decrypt with PBKDF2")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode")
    parser.add_argument("input_file", help="Input file path")
    parser.add_argument("output_file", help="Output file path")
    parser.add_argument("-p", "--password", required=True, help="Password for key derivation")

    args = parser.parse_args()

    if args.mode == "encrypt":
        with open(args.input_file, "rb") as f:
            plaintext = f.read()
        encrypted = encrypt(plaintext, args.password)
        with open(args.output_file, "w") as f:
            f.write(encrypted)
        print(f"[+] File encrypted and saved to {args.output_file}")

    elif args.mode == "decrypt":
        with open(args.input_file, "r") as f:
            encrypted = f.read()
        try:
            decrypted = decrypt(encrypted, args.password)
            with open(args.output_file, "wb") as f:
                f.write(decrypted)
            print(f"[+] File decrypted and saved to {args.output_file}")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")

if __name__ == "__main__":
    main()

