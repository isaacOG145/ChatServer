from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, join_room, leave_room, send
from crypto_utils import decrypt_message, encrypt_message
import json
import os
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave-super-secreta'
socketio = SocketIO(app, cors_allowed_origins="*")

ROOMS_FILE = 'rooms.json'

# ------------------ Funciones de soporte ------------------

def load_rooms():
    if not os.path.exists(ROOMS_FILE):
        with open(ROOMS_FILE, 'w') as f:
            json.dump({"general": []}, f)
    with open(ROOMS_FILE, 'r') as f:
        return json.load(f)

def save_rooms(rooms):
    with open(ROOMS_FILE, 'w') as f:
        json.dump(rooms, f, indent=4)

# ------------------ Rutas principales ------------------

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
    rooms = load_rooms()
    return render_template('chat.html', username=session['username'], rooms=list(rooms.keys()))

# ------------------ Eventos de Socket.IO ------------------

@socketio.on('join')
def handle_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    send(f"{username} se unió al chat.", to=room)

@socketio.on('message')
def handle_message(data):
    username = data['username']
    ciphertext = data['msg']
    nonce = data['nonce']
    room = data['room']

    # Medir tiempo de descifrado
    start_dec = time.perf_counter()
    msg = decrypt_message(ciphertext, nonce)
    end_dec = time.perf_counter()

    # Medir tiempo de cifrado (solo para análisis, no reenviaremos cifrado)
    start_enc = time.perf_counter()
    _ = encrypt_message(f"{username}: {msg}")  # simulamos re-cifrado
    end_enc = time.perf_counter()

    # Mostrar datos en consola
    print("------------------------------------------------")
    print(f"[{room}] {username}: {msg}")
    print(f"🔒 Tipo de cifrado: AES-GCM (simétrico)")
    print(f"⏱ Tiempo descifrado: {(end_dec - start_dec) * 1000:.4f} ms")
    print(f"⏱ Tiempo cifrado: {(end_enc - start_enc) * 1000:.4f} ms")
    print("------------------------------------------------")

    # ✅ Reenviamos texto plano para mostrarlo en el chat
    send(f"{username}: {msg}", to=room)


@socketio.on('leave')
def handle_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    send(f"{username} salió del chat.", to=room)

# ------------------ Main ------------------

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
