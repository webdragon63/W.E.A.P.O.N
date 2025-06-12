import argparse

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_encrypt_hex(data, key):
    encrypted = xor_encrypt(data.encode(), key.encode())
    return encrypted.hex()

def xor_decrypt_hex(hexdata, key):
    encrypted = bytes.fromhex(hexdata)
    return xor_encrypt(encrypted, key.encode()).decode()

def main():
    parser = argparse.ArgumentParser(description="XOR Encrypt or Decrypt Hex String")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("input", help="Input string (plaintext for encrypt, hex for decrypt)")
    parser.add_argument("key", help="Encryption key")

    args = parser.parse_args()

    if args.mode == "encrypt":
        result = xor_encrypt_hex(args.input, args.key)
        print(f"Encrypted hex: {result}")
    else:
        try:
            result = xor_decrypt_hex(args.input, args.key)
            print(f"Decrypted string: {result}")
        except Exception as e:
            print(f"[!] Decryption error: {e}")

if __name__ == "__main__":
    main()

