import argparse
import os
import base64

def generate_key(length=32):
    key = os.urandom(length)
    print(f"[+] Generated Key ({length} bytes):")
    print(f" - Raw (hex): {key.hex()}")
    print(f" - Base64: {base64.b64encode(key).decode()}")

def main():
    parser = argparse.ArgumentParser(description="Random Key Generator")
    parser.add_argument("-l", "--length", type=int, default=32, help="Length of key in bytes (default: 32)")
    args = parser.parse_args()
    
    generate_key(args.length)

if __name__ == "__main__":
    main()

