from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, join_room, leave_room, send
from dotenv import load_dotenv
import json
import os
import base64
import hashlib
import time
from datetime import datetime
from crypto_utils import generate_keys, load_keys
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random

# ------------------ Cargar .env ------------------
load_dotenv()

HOST_URL = os.getenv("HOST_URL", "0.0.0.0")
HOST_PORT = int(os.getenv("HOST_PORT", 5000))
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret")
CORS_ALLOWED = os.getenv("CORS_ALLOWED", "*")

# ------------------ Flask ------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins=CORS_ALLOWED)

ROOMS_FILE = "rooms.json"

# ------------------ Cargar llaves ------------------
generate_keys()
PRIVATE_KEY, PUBLIC_KEY = load_keys()


# ------------------ Soporte ------------------
def load_rooms():
    if not os.path.exists(ROOMS_FILE):
        with open(ROOMS_FILE, 'w') as f:
            json.dump({"general": []}, f)
    with open(ROOMS_FILE, 'r') as f:
        return json.load(f)


# ------------------ Rutas ------------------
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        if username.strip() == "":
            return render_template('login.html', error="Debes ingresar un nombre.")
        session['username'] = username
        return redirect(url_for('chat'))

    return render_template('login.html')


@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template(
        'chat.html',
        username=session['username'],
        socket_host=os.getenv("SOCKET_HOST", "http://localhost"),
        socket_port=os.getenv("HOST_PORT", 5000)
    )

@app.route('/public_key')
def public_key():
    return PUBLIC_KEY.export_key().decode()


# ------------------ Eventos Socket.IO ------------------
@socketio.on('join')
def handle_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
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

        # Separar mensaje y hash
        if "|HASH|" not in payload_str:
            print("Error: mensaje inválido")
            return

        msg, received_hash = payload_str.split("|HASH|", 1)

        # Validar integridad
        calculated_hash = hashlib.sha256(msg.encode()).hexdigest()
        integrity_ok = (calculated_hash == received_hash)

    except Exception as e:
        print("Error al descifrar mensaje:", e)
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n──── Mensaje recibido ─────────────")
    print(f"Hora: {timestamp}")
    print(f"Usuario: {username}")
    print(f"Mensaje: {msg}")
    print(f"Integridad: {'OK ✔' if integrity_ok else 'FALLÓ ✘'}")
    print(f"Tiempo descifrado: {decryption_time:.4f} ms")
    print("──────────────────────────────────\n")

    if integrity_ok:
        send(f"{username}: {msg}", to=room)
    else:
        send(f"⚠ Mensaje corrupto de {username}", to=room)


@socketio.on('leave')
def handle_leave(data):
    leave_room(data["room"])
    send(f"{data['username']} salió del chat.", to=data["room"])


# ------------------ Run ------------------
if __name__ == '__main__':
    socketio.run(app, host=HOST_URL, port=HOST_PORT, debug=True)
