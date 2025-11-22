from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, join_room, leave_room, send
from dotenv import load_dotenv
import json
import os
import base64
import hashlib
import time
from crypto_utils import generate_keys, load_keys
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random

load_dotenv()

HOST_URL = os.getenv("HOST_URL", "0.0.0.0")
HOST_PORT = int(os.getenv("HOST_PORT", 5000))
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret")
CORS_ALLOWED = os.getenv("CORS_ALLOWED", "*")

app = Flask(__name__, 
    static_folder='static',     
    static_url_path='/static'   
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
        # Si el archivo está corrupto, crear uno nuevo
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

@app.route('/', methods=['GET', 'POST'])
def oauth_login():
    """Nueva página principal - Login con OAuth"""
    if request.method == 'POST':
        # Tu lógica de autenticación OAuth aquí
        code = request.form.get('code')
        # ... procesar OAuth ...
        
        # Si la autenticación es exitosa
        session['username'] = "usuario_oauth"
        return redirect(url_for('chat'))
    
    # GET request - mostrar formulario OAuth
    return render_template('oauthLogin.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Usuario')
    session.pop('username', None)
    print(f"{username} cerró sesión")
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'username' not in session:
        print("Acceso denegado a /chat - no hay sesión")
        return redirect(url_for('login'))

    print(f"Usuario {session['username']} accedió al chat")
    return render_template(
        'chat.html',
        username=session['username'],
        socket_host=os.getenv("SOCKET_HOST", "http://localhost"),
        socket_port=os.getenv("HOST_PORT", 5000)
    )

@app.route('/public_key')
def public_key():
    return PUBLIC_KEY.export_key().decode()

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

        start_dec = time.perf_counter()

        sentinel = Random.new().read(15 + len(encrypted_bytes))
        decrypted_payload = cipher_rsa.decrypt(encrypted_bytes, sentinel)
        payload_str = decrypted_payload.decode()

        end_dec = time.perf_counter()
        decryption_time = (end_dec - start_dec) * 1000

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
    print(f"Archivos de usuarios: {USERS_FILE}")
    print("=" * 50)
    socketio.run(app, host=HOST_URL, port=HOST_PORT, debug=True)