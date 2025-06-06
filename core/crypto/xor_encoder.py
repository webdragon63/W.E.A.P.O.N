def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_encrypt_hex(data, key):
    encrypted = xor_encrypt(data.encode(), key.encode())
    return encrypted.hex()

def xor_decrypt_hex(hexdata, key):
    encrypted = bytes.fromhex(hexdata)
    return xor_encrypt(encrypted, key.encode()).decode()

