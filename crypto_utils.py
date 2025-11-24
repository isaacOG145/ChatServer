import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from dotenv import load_dotenv

load_dotenv()

PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY", "keys/private.pem")
PUBLIC_KEY_PATH = os.getenv("PUBLIC_KEY", "keys/public.pem")


def generate_keys():
    key_dir = os.path.dirname(PRIVATE_KEY_PATH)

    if key_dir and not os.path.exists(key_dir):
        os.makedirs(key_dir)

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
    
def sign_data(data, private_key):
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    file_hash = SHA256.new(data)
    
    signature = pkcs1_15.new(private_key).sign(file_hash)
    
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data, signature, public_key):
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        
        signature_bytes = base64.b64decode(signature)
        
        file_hash = SHA256.new(data)
        
        pkcs1_15.new(public_key).verify(file_hash, signature_bytes)
        return True
    except (ValueError, TypeError):
        return False

def sign_file(file_path, private_key):
    
    with open(file_path, 'rb') as f:
        file_data = f.read()
    return sign_data(file_data, private_key)

def generate_digital_signature_info(username, timestamp, private_key):
    
    data_to_sign = f"{username}|{timestamp}"
    signature = sign_data(data_to_sign, private_key)
    return {
        'signed_by': username,
        'timestamp': timestamp,
        'signature': signature
    }
def create_signed_document(original_data, signature, metadata):
    
    import json
    
    signed_doc = {
        "format": "PKCS7-Like",
        "version": "1.0",
        "content_b64": base64.b64encode(original_data).decode('utf-8'),
        "signature_b64": signature,
        "metadata": {
            "signed_by": metadata['signed_by'],
            "timestamp": metadata['timestamp'],
            "algorithm": "RSA-SHA256",
            "hash_algorithm": "SHA256"
        }
    }
    return json.dumps(signed_doc, indent=2)

def extract_from_signed_document(signed_document_json):

    import json
    
    doc = json.loads(signed_document_json)
    original_data = base64.b64decode(doc['content_b64'])
    signature = doc['signature_b64']
    metadata = doc['metadata']
    
    return original_data, signature, metadata