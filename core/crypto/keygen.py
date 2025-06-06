import os
import base64

def generate_key(length=32):
    key = os.urandom(length)
    print(f"Raw: {key.hex()}")
    print(f"Base64: {base64.b64encode(key).decode()}")

if __name__ == "__main__":
    generate_key()

