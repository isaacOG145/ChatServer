import jwt
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

class JWTManager:
    def __init__(self):
        self.secret_key = os.getenv("SECRET_KEY", "default_secret")
        self.algorithm = "HS256"
    
    def generate_token(self, username, auth_method):
        """
        Genera un token JWT
        """
        payload = {
            'username': username,
            'auth_method': auth_method,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
    
    def verify_token(self, token):
        """
        Verifica y decodifica un token JWT
        """
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            print("Token expirado")
            return None
        except jwt.InvalidTokenError as e:
            print(f"Token inválido: {e}")
            return None
jwt_manager = JWTManager()