from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import base64

def encrypt(message, key):
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt(enc_message, key):
    raw = base64.b64decode(enc_message)
    nonce = raw[:12]
    tag = raw[12:28]
    ciphertext = raw[28:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

