import base64
import argparse
import hashlib

DEFAULT_MASK = 0x42424242424242

def xor_obfuscate_key(real_key: int, mask: int = DEFAULT_MASK) -> tuple[str, int]:
    """XORs the real key with a mask and returns base64 obfuscated string and mask."""
    obfuscated = real_key ^ mask
    obf_bytes = obfuscated.to_bytes((obfuscated.bit_length() + 7) // 8, byteorder="big")
    return base64.b64encode(obf_bytes).decode(), mask

def derive_int_key(key_str: str) -> int:
    """Derives a consistent 64-bit int from a string using SHA-256."""
    hash_digest = hashlib.sha256(key_str.encode()).digest()
    return int.from_bytes(hash_digest[:8], byteorder="big")  # 64-bit int

def show_usage(real_key: int, b64_key: str, mask: int):
    """Displays usage instructions for encoded key and mask."""
    print(f"\n[!] Replace key value with this key {real_key} inside `core/beacon/src/encoder.py`")
    print("\nUse this b and m value in your builder inside `core/beacon/src/builder.py`:\n")
    print(f'b = "{b64_key}"')
    print(f'm = {hex(mask)}\n')

def main():
    parser = argparse.ArgumentParser(description="Obfuscate a key using XOR + Base64.")
    parser.add_argument("--key", required=True, help="Real key (string or integer)")
    parser.add_argument("--mask", type=lambda x: int(x, 0), default=DEFAULT_MASK, help="XOR mask (e.g. 0x4242...)")

    args = parser.parse_args()

    try:
        # Try integer first; fallback to hashing a string
        try:
            real_key = int(args.key)
        except ValueError:
            real_key = derive_int_key(args.key)

        b64_key, mask = xor_obfuscate_key(real_key, args.mask)
        show_usage(real_key, b64_key, mask)

    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()

