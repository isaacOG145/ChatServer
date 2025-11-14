#app.py
from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, join_room, leave_room, send
import json
import os
import base64
import hashlib
from crypto_utils import generate_keys, load_keys
from Crypto.Cipher import PKCS1_v1_5 
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave-super-secreta'
socketio = SocketIO(app, cors_allowed_origins="*")

ROOMS_FILE = 'rooms.json'

# ------------------ Cargar llaves RSA ------------------
generate_keys()
PRIVATE_KEY, PUBLIC_KEY = load_keys()

# ------------------ Funciones de soporte ------------------

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
    return render_template('chat.html', username=session['username'])

# Endpoint para entregar la clave pública al frontend
@app.route('/public_key')
def public_key():
    return PUBLIC_KEY.export_key().decode()

# ------------------ Eventos de Socket.IO ------------------

@socketio.on('join')
def handle_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    send(f"{username} se unió al chat.", to=room)

@socketio.on('message')
def handle_message(data):
    from datetime import datetime
    import time, hashlib

    username = data['username']
    encrypted_b64 = data['msg']
    room = data['room']

    try:
        encrypted_bytes = base64.b64decode(encrypted_b64)
        cipher_rsa = PKCS1_v1_5.new(PRIVATE_KEY)

        start_dec = time.perf_counter()

        from Crypto import Random
        sentinel = Random.new().read(15 + len(encrypted_bytes))
        decrypted_payload = cipher_rsa.decrypt(encrypted_bytes, sentinel)
        payload_str = decrypted_payload.decode()

        end_dec = time.perf_counter()
        decryption_time = (end_dec - start_dec) * 1000

        # Separar mensaje y hash
        if "|HASH|" not in payload_str:
            print("Error: Formato de mensaje inválido")
            return
        
        msg, received_hash = payload_str.split("|HASH|", 1)

        # Calcular hash del mensaje descifrado
        calculated_hash = hashlib.sha256(msg.encode()).hexdigest()

        integrity_ok = (calculated_hash == received_hash)

    except Exception as e:
        print("Error al descifrar mensaje:", e)
        import traceback
        traceback.print_exc()
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n──── Mensaje recibido ─────────────────────────────")
    print(f"Timestamp:     {timestamp}")
    print(f"User:          {username}")
    print(f"Mensaje:       {msg}")
    print(f"Room:          {room}")
    print(f"Algoritmo:     RSA + PKCS1_v1_5 + sha256 (Asimétrico)")
    print(f"Integridad:     {'OK ✔' if integrity_ok else 'FALLÓ ✘'}")
    print(f"Tiempo descifrado (server): {decryption_time:.4f} ms")
    print("───────────────────────────────────────────────────\n")

    if integrity_ok:
        send(f"{username}: {msg}", to=room)
    else:
        send(f"Mensaje corrupto o manipulado de {username}", to=room)


@socketio.on('leave')
def handle_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    send(f"{username} salió del chat.", to=room)

# ------------------ Run ------------------

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)