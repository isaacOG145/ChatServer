# crypto_utils.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import base64

def generate_keys():
    if not os.path.exists("keys"):
        os.makedirs("keys")

    private_path = "keys/private.pem"
    public_path = "keys/public.pem"

    if not os.path.exists(private_path) or not os.path.exists(public_path):
        key = RSA.generate(2048)
        with open(private_path, "wb") as f:
            f.write(key.export_key())
        with open(public_path, "wb") as f:
            f.write(key.publickey().export_key())
        print("Llaves RSA generadas correctamente.")
    else:
        print("Llaves ya existentes, no se regeneran.")

def load_keys():
    try:
        private_key = RSA.import_key(open("keys/private.pem", "rb").read())
        public_key = RSA.import_key(open("keys/public.pem", "rb").read())
        return private_key, public_key
    except FileNotFoundError as e:
        print(f"Error: No se encontraron las claves - {e}")
        return None, None
    except Exception as e:
        print(f"Error cargando claves: {e}")
        return None, None

def encrypt_message(public_key, message: str) -> str:
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_bytes = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted_bytes).decode()

def decrypt_message(private_key, encrypted_b64: str) -> str:
    try:
        encrypted_bytes = base64.b64decode(encrypted_b64)
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(encrypted_bytes).decode('utf-8')
    except Exception as e:
        print("Error desencriptando:", e)
        return None
