from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from flask_socketio import SocketIO, join_room, leave_room, send
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
import json
import os
import base64
import hashlib
import time
from crypto_utils import generate_keys, load_keys
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
from jwt_utils import jwt_manager

load_dotenv()

HOST_URL = os.getenv("HOST_URL", "0.0.0.0")
HOST_PORT = int(os.getenv("HOST_PORT", 5000))
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret")
CORS_ALLOWED = os.getenv("CORS_ALLOWED", "*")

app = Flask(__name__, 
    static_folder='static',     
    static_url_path='/static'   
)

# Configuración CORREGIDA de OAuth - SIN metadata
oauth = OAuth(app)

# Configuración manual completa de Google OAuth
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',  # ← Agregar jwks_uri
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account',
    },
    # Configuración adicional para OpenID Connect
    api_base_url='https://www.googleapis.com/oauth2/v3/'
)

app.config['SECRET_KEY'] = SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins=CORS_ALLOWED)

ROOMS_FILE = "rooms.json"
USERS_FILE = "users.json"

generate_keys()
PRIVATE_KEY, PUBLIC_KEY = load_keys()

def load_rooms():
    if not os.path.exists(ROOMS_FILE):
        with open(ROOMS_FILE, 'w') as f:
            json.dump({"general": []}, f)
    with open(ROOMS_FILE, 'r') as f:
        return json.load(f)

def load_users():
    """Carga usuarios del archivo JSON"""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
        return {}
    
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
        return {}

def save_users(users):
    """Guarda usuarios en el archivo JSON"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def hash_password(password):
    """Hash simple de contraseña con SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    """Verifica si la contraseña coincide con el hash"""
    return stored_hash == hash_password(password)


def login_user(username, auth_method, email=None):
    """
    Función unificada para login que genera JWT
    """
    # Generar token JWT
    token = jwt_manager.generate_token(username, auth_method)
    
    # Mantener session de Flask
    session['username'] = username
    session['auth_method'] = auth_method
    session['logged_in'] = True
    if email:
        session['email'] = email
    
    # Crear response y setear cookie JWT
    response = redirect(url_for('room'))
    response.set_cookie(
        'auth_token',
        token,
        httponly=True,
        secure=False,
        samesite='Lax',
        max_age=24*60*60
    )
    
    print(f"Login exitoso: {username} via {auth_method}")
    return response

@app.route('/', methods=['GET', 'POST'])
def login():
    """Página principal - Maneja ambos tipos de login"""
    if request.method == 'POST':
        # Detectar qué tipo de login es
        if 'google_login' in request.form:
            # Redirigir a Google OAuth
            print("Iniciando flujo OAuth de Google...")
            redirect_uri = 'http://localhost:5000/google-callback'
            print(f"Redirect URI: {redirect_uri}")
            return oauth.google.authorize_redirect(redirect_uri)
        
        else:
            # Login tradicional (tu código existente)
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            # Validación básica
            if not username or not password:
                return render_template('oauthLogin.html', error="Usuario y contraseña son obligatorios.")
            
            if len(username) < 3:
                return render_template('oauthLogin.html', error="El usuario debe tener al menos 3 caracteres.")
            
            if len(password) < 4:
                return render_template('oauthLogin.html', error="La contraseña debe tener al menos 4 caracteres.")
            
            users = load_users()
            
            # Registro automático si el usuario no existe
            if username not in users:
                print(f"Registrando nuevo usuario: {username}")
                users[username] = {
                    'password_hash': hash_password(password),
                    'created_at': time.time(),
                    'auth_method': 'traditional'
                }
                save_users(users)
                return login_user(username, 'traditional')
            
            # Login si el usuario ya existe
            print(f"Usuario {username} ya existe, verificando contraseña...")
            if not verify_password(users[username]['password_hash'], password):
                return render_template('oauthLogin.html', error="Contraseña incorrecta.")
            
            return login_user(username, 'traditional')
    
    # GET request - mostrar formulario
    return render_template('oauthLogin.html')

@app.route('/google-callback')
def google_callback():
    """Callback de Google OAuth"""
    try:
        print("Procesando callback de Google...")
        
        # Obtener token de Google
        token = oauth.google.authorize_access_token()
        print(f"Token recibido: {token}")
        
        # Obtener información del usuario - método directo
        resp = oauth.google.get('userinfo')
        user_info = resp.json()
        print(f"Información de usuario: {user_info}")
        
        # Extraer datos relevantes
        google_id = user_info.get('sub')
        email = user_info.get('email')
        name = user_info.get('name')
        picture = user_info.get('picture')
        
        if not email:
            return redirect(url_for('login', error="No se pudo obtener el email de Google"))
        
        print(f"Usuario autenticado: {email}")
        
        # Crear username a partir del email
        username = email.split('@')[0]
        
        # Guardar/actualizar usuario en nuestro sistema
        users = load_users()
        
        # Si el usuario no existe, crearlo
        if username not in users:
            print(f"Registrando nuevo usuario via Google: {username}")
            users[username] = {
                'google_id': google_id,
                'email': email,
                'name': name,
                'picture': picture,
                'created_at': time.time(),
                'auth_method': 'google'
            }
            save_users(users)
        else:
            # Actualizar información de usuario existente
            print(f"Actualizando usuario existente via Google: {username}")
            users[username].update({
                'google_id': google_id,
                'email': email,
                'name': name,
                'picture': picture,
                'auth_method': 'google'
            })
            save_users(users)
        
        # Hacer login del usuario
        return login_user(username, 'google', email=email)
        
    except Exception as e:
        print(f"Error en Google OAuth: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('login', error=f"Error en autenticación con Google: {str(e)}"))

@app.route('/room')
def room():
    """Página de prueba para verificar autenticación"""
    try:
        # Verificar JWT primero
        token = request.cookies.get('auth_token')
        print(f"Token encontrado: {bool(token)}")
        
        if token:
            payload = jwt_manager.verify_token(token)
            print(f"Payload JWT: {payload}")
            if payload:
                print(f"Acceso a room via JWT: {payload['username']}")
                return render_template('room.html', username=payload['username'])
        
        # Fallback a session
        if 'username' in session:
            print(f"Acceso a room via session: {session['username']}")
            return render_template('room.html', username=session['username'])
        
        # No autenticado
        print("Acceso denegado a room - no autenticado")
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"ERROR en /room: {e}")
        import traceback
        traceback.print_exc()
        return f"Error: {e}", 500

@app.route('/verify-token')
def verify_token():
    """Endpoint para verificar el token JWT (para debugging)"""
    token = request.cookies.get('auth_token')
    if not token:
        return jsonify({'valid': False, 'error': 'No token provided'})
    
    payload = jwt_manager.verify_token(token)
    if payload:
        return jsonify({
            'valid': True, 
            'user': payload
        })
    else:
        return jsonify({'valid': False, 'error': 'Invalid token'})

@app.route('/logout')
def logout():
    """Logout - limpia session y cookie JWT"""
    username = session.get('username', 'Usuario')
    session.clear()
    response = redirect(url_for('login'))
    response.set_cookie('auth_token', '', expires=0)
    print(f"{username} cerró sesión")
    return response

@app.route('/public_key')
def public_key():
    return PUBLIC_KEY.export_key().decode()

# SocketIO Handlers
@socketio.on('join')
def handle_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    print(f"{username} se unió a {room}")
    send(f"{username} se unió al chat.", to=room)

@socketio.on('message')
def handle_message(data):
    username = data['username']
    encrypted_b64 = data['msg']
    room = data['room']

    try:
        encrypted_bytes = base64.b64decode(encrypted_b64)
        cipher_rsa = PKCS1_v1_5.new(PRIVATE_KEY)

        sentinel = Random.new().read(15 + len(encrypted_bytes))
        decrypted_payload = cipher_rsa.decrypt(encrypted_bytes, sentinel)
        payload_str = decrypted_payload.decode()

        if "|HASH|" not in payload_str:
            print("Error: mensaje inválido")
            return

        msg, received_hash = payload_str.split("|HASH|", 1)
        calculated_hash = hashlib.sha256(msg.encode()).hexdigest()
        integrity_ok = (calculated_hash == received_hash)

    except Exception as e:
        print("Error al descifrar mensaje:", e)
        return

    if integrity_ok:
        print(f"[{room}] {username}: {msg}")
        send(f"{username}: {msg}", to=room)
    else:
        print(f"Mensaje corrupto de {username}")
        send(f"Mensaje corrupto de {username}", to=room)

@socketio.on('leave')
def handle_leave(data):
    username = data["username"]
    room = data["room"]
    leave_room(room)
    print(f"{username} salió de {room}")
    send(f"{username} salió del chat.", to=room)

if __name__ == '__main__':
    print("=" * 50)
    print("Iniciando servidor de chat seguro...")
    print(f"Host: {HOST_URL}:{HOST_PORT}")
    print(f"Google OAuth: CONFIGURADO")
    print("=" * 50)
    socketio.run(app, host=HOST_URL, port=HOST_PORT, debug=True)