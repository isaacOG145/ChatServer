# crypto_utils.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import base64
from dotenv import load_dotenv

load_dotenv()

PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY", "keys/private.pem")
PUBLIC_KEY_PATH = os.getenv("PUBLIC_KEY", "keys/public.pem")


def generate_keys():
    key_dir = os.path.dirname(PRIVATE_KEY_PATH)

    # Crear carpeta si no existe
    if key_dir and not os.path.exists(key_dir):
        os.makedirs(key_dir)

    # Generar llaves si no existen
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        key = RSA.generate(2048)

        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(key.export_key())

        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(key.publickey().export_key())

        print("Llaves RSA generadas correctamente.")
    else:
        print("Llaves ya existentes, no se regeneran.")


def load_keys():
    try:
        private_key = RSA.import_key(open(PRIVATE_KEY_PATH, "rb").read())
        public_key = RSA.import_key(open(PUBLIC_KEY_PATH, "rb").read())
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
