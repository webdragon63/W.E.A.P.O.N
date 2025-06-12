import base64

def generate_obfuscated_key(real_key: int, mask: int = 0x42424242424242):
    # XOR the real key with the mask
    obfuscated = real_key ^ mask

    # Convert to bytes
    obf_bytes = obfuscated.to_bytes((obfuscated.bit_length() + 7) // 8, byteorder="big")

    # Base64 encode
    b64_key = base64.b64encode(obf_bytes).decode()

    print("\nUse this in your payload:")
    print(f'b = "{b64_key}"')
    print(f'm = {hex(mask)}')

if __name__ == "__main__":
    try:
        real_key = int(input("Enter the integer key: "))
        generate_obfuscated_key(real_key)
    except ValueError:
        print("[!] Please enter a valid integer key.")

