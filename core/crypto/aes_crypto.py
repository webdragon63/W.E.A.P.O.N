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
    ciphertext = cipher.encrypt(pad(data.encode()))
    return base64.b64encode(salt + iv + ciphertext).decode()

def decrypt(enc_data, password):
    raw = base64.b64decode(enc_data)
    salt = raw[:SALT_SIZE]
    iv = raw[SALT_SIZE:SALT_SIZE+BLOCK_SIZE]
    ciphertext = raw[SALT_SIZE+BLOCK_SIZE:]
    key = PBKDF2(password, salt, dkLen=KEY_LEN)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext)).decode()

