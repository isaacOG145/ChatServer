from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, join_room, leave_room, send
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave-super-secreta'
socketio = SocketIO(app, cors_allowed_origins="*")

ROOMS_FILE = 'rooms.json'

def load_rooms():
    if not os.path.exists(ROOMS_FILE):
        with open(ROOMS_FILE, 'w') as f:
            json.dump({"general": []}, f)
    with open(ROOMS_FILE, 'r') as f:
        return json.load(f)

def save_rooms(rooms):
    with open(ROOMS_FILE, 'w') as f:
        json.dump(rooms, f, indent=4)

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

@socketio.on('join')
def handle_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    send(f"{username} se unió al chat.", to=room)

@socketio.on('message')
def handle_message(data):
    username = data['username']
    msg = data['msg']
    room = data['room']
    print(f"[{room}] {username}: {msg}")
    send(f"{username}: {msg}", to=room)

@socketio.on('leave')
def handle_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    send(f"{username} salió del chat.", to=room)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
