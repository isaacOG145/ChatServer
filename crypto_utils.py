import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Clave fija de 32 bytes (igual que en JS)
SECRET_KEY = bytes([
    1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32
])

def encrypt_message(message: str) -> bytes:
    aesgcm = AESGCM(SECRET_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    # Empaquetamos ambos en Base64 concatenado
    return base64.b64encode(ciphertext)

def decrypt_message(ciphertext_b64: str, nonce_b64: str) -> str:
    aesgcm = AESGCM(SECRET_KEY)
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')
