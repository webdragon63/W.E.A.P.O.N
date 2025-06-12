import argparse
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import base64
import os
import hashlib

def encrypt(message, key):
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt(enc_message, key):
    raw = base64.b64decode(enc_message)
    nonce = raw[:12]
    tag = raw[12:28]
    ciphertext = raw[28:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def derive_key(password):
    # Derive a 32-byte key from the password using SHA-256
    return hashlib.sha256(password.encode()).digest()

def main():
    parser = argparse.ArgumentParser(description="ChaCha20-Poly1305 Encrypt/Decrypt")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode")
    parser.add_argument("input_file", help="Input file path")
    parser.add_argument("output_file", help="Output file path")
    parser.add_argument("-p", "--password", required=True, help="Password to derive key")

    args = parser.parse_args()

    key = derive_key(args.password)

    if args.mode == "encrypt":
        with open(args.input_file, "rb") as f:
            plaintext = f.read()
        encrypted = encrypt(plaintext, key)
        with open(args.output_file, "w") as f:
            f.write(encrypted)
        print(f"[+] File encrypted and saved to {args.output_file}")

    elif args.mode == "decrypt":
        with open(args.input_file, "r") as f:
            encrypted = f.read()
        try:
            decrypted = decrypt(encrypted, key)
            with open(args.output_file, "wb") as f:
                f.write(decrypted)
            print(f"[+] File decrypted and saved to {args.output_file}")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")

if __name__ == "__main__":
    main()

