from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from flask_socketio import SocketIO, join_room, leave_room, send
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
import json
import os
import base64
import hashlib
import time
from crypto_utils import (
    generate_keys,load_keys, sign_data, generate_digital_signature_info, verify_signature,
    create_signed_document, extract_from_signed_document  # ← Solo estas quedan
)
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

oauth = OAuth(app)

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
    
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def hash_password(password):
    
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    
    return stored_hash == hash_password(password)

def get_user_keys(username):
    
    users = load_users()
    user_data = users.get(username, {})
    
    if 'public_key' not in user_data or 'private_key' not in user_data:
        print(f"Usuario {username} no tiene claves configuradas")
        return None, None
    
    try:
        
        from Crypto.PublicKey import RSA
        private_key = RSA.import_key(user_data['private_key'])
        public_key = RSA.import_key(user_data['public_key'])
        return private_key, public_key
    except Exception as e:
        print(f"Error cargando claves de {username}: {e}")
        return None, None

def login_user(username, auth_method, email=None):
    
    token = jwt_manager.generate_token(username, auth_method)
    
    session['username'] = username
    session['auth_method'] = auth_method
    session['logged_in'] = True
    if email:
        session['email'] = email
    
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
       
        if 'google_login' in request.form:
           
            print("Iniciando flujo OAuth de Google...")
            redirect_uri = 'http://localhost:5000/google-callback'
            return oauth.google.authorize_redirect(redirect_uri)
        
        else:
            
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            if not username or not password:
                return render_template('oauthLogin.html', error="Usuario y contraseña son obligatorios.")
            
            if len(username) < 3:
                return render_template('oauthLogin.html', error="El usuario debe tener al menos 3 caracteres.")
            
            if len(password) < 4:
                return render_template('oauthLogin.html', error="La contraseña debe tener al menos 4 caracteres.")
            
            users = load_users()
            
            if username not in users:
                print(f"Registrando nuevo usuario: {username}")
                
                
                users[username] = {
                    'password_hash': hash_password(password),
                    'created_at': time.time(),
                    'auth_method': 'traditional',
                }
                save_users(users)
                return login_user(username, 'traditional')
            
            print(f"Usuario {username} ya existe, verificando contraseña...")
            if not verify_password(users[username]['password_hash'], password):
                return render_template('oauthLogin.html', error="Contraseña incorrecta.")
            
            return login_user(username, 'traditional')
    
    return render_template('oauthLogin.html')

@app.route('/google-callback')
def google_callback():
    
    try:
        
        token = oauth.google.authorize_access_token()
        
        resp = oauth.google.get('userinfo')
        user_info = resp.json()
        
        email = user_info.get('email')
        if not email:
            return redirect(url_for('login', error="No se pudo obtener el email de Google"))
        
        print(f"Usuario autenticado: {email}")
        
        username = email.split('@')[0]
        
        users = load_users()
        
        if username not in users:
            print(f"Registrando nuevo usuario via Google: {username}")
            
            users[username] = {
                'google_id': user_info.get('sub'),
                'email': email,
                'name': user_info.get('name'),
                'picture': user_info.get('picture'),
                'created_at': time.time(),
                'auth_method': 'google',
            }
            save_users(users)
        else:
            
            print(f"Actualizando usuario existente via Google: {username}")
            
            users[username].update({
                'google_id': user_info.get('sub'),
                'email': email,
                'name': user_info.get('name'),
                'picture': user_info.get('picture'),
                'auth_method': 'google'
            })
            save_users(users)
        
        return login_user(username, 'google', email=email)
        
    except Exception as e:
        print(f"Error en Google OAuth: {e}")
        return redirect(url_for('login', error=f"Error en autenticación con Google: {str(e)}"))

@app.route('/room')
def room():
    
    try:
    
        token = request.cookies.get('auth_token')
        print(f"Token encontrado: {bool(token)}")
        
        if token:
            payload = jwt_manager.verify_token(token)
            print(f"Payload JWT: {payload}")
            if payload:
                print(f"Acceso a room via JWT: {payload['username']}")
                return render_template('room.html', username=payload['username'])

        if 'username' in session:
            print(f"Acceso a room via session: {session['username']}")
            return render_template('room.html', username=session['username'])
        
        print("Acceso denegado a room - no autenticado")
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"ERROR en /room: {e}")
        import traceback
        traceback.print_exc()
        return f"Error: {e}", 500

@app.route('/verify-token')
def verify_token():

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
    
    username = session.get('username', 'Usuario')
    session.clear()
    response = redirect(url_for('login'))
    response.set_cookie('auth_token', '', expires=0)
    print(f"{username} cerró sesión")
    return response

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

@app.route('/manual-signature')
def manual_signature():

    token = request.cookies.get('auth_token')
    if token:
        payload = jwt_manager.verify_token(token)
        if payload:
            return render_template('manual_signature.html', username=payload['username'])
    
    if 'username' in session:
        return render_template('manual_signature.html', username=session['username'])
    
    return redirect(url_for('login'))

@app.route('/api/sign-file', methods=['POST'])
def api_sign_file():
    
    try:
        
        token = request.cookies.get('auth_token')
        if not token:
            return jsonify({'error': 'No autenticado'}), 401
        
        payload = jwt_manager.verify_token(token)
        if not payload:
            return jsonify({'error': 'Token inválido'}), 401
        
        username = payload['username']
        
        user_private_key, user_public_key = get_user_keys(username)
        if not user_private_key:
            return jsonify({'error': 'Usuario no tiene claves configuradas'}), 400
        
        if 'file' not in request.files:
            return jsonify({'error': 'No se proporcionó archivo'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nombre de archivo vacío'}), 400
        
        file_data = file.read()
        signature = sign_data(file_data, user_private_key)  # ← Usar clave del usuario
        
        timestamp = time.time()
        signature_info = generate_digital_signature_info(username, timestamp, user_private_key)
        
        return jsonify({
            'success': True,
            'filename': file.filename,
            'signature': signature,
            'signature_info': signature_info,
            'signed_by': username,
            'timestamp': timestamp,
            'public_key': user_public_key.export_key().decode('utf-8')  
        })
        
    except Exception as e:
        print(f"Error firmando archivo: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-signature', methods=['POST'])
def api_verify_signature():
    
    try:
        data = request.json
        file_data = data.get('file_data', '').encode('utf-8')
        signature = data.get('signature', '')
        signed_by = data.get('signed_by', '')
        
        if not signed_by:
            return jsonify({'error': 'Se requiere el nombre del firmante'}), 400
        
        _, signer_public_key = get_user_keys(signed_by)
        if not signer_public_key:
            return jsonify({'error': f'No se encontró clave pública para {signed_by}'}), 404
        
        is_valid = verify_signature(file_data, signature, signer_public_key)
        
        return jsonify({
            'valid': is_valid,
            'signed_by': signed_by,
            'verified_with': f'Clave pública de {signed_by}',
            'verification_time': time.time()
        })
        
    except Exception as e:
        print(f"Error verificando firma: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/create-signed-document', methods=['POST'])
def api_create_signed_document():
    
    try:
        token = request.cookies.get('auth_token')
        if not token:
            return jsonify({'error': 'No autenticado'}), 401
        
        payload = jwt_manager.verify_token(token)
        if not payload:
            return jsonify({'error': 'Token inválido'}), 401
        
        username = payload['username']
        user_private_key, _ = get_user_keys(username)
        
        if 'file' not in request.files:
            return jsonify({'error': 'No se proporcionó archivo'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nombre de archivo vacío'}), 400
        
        file_data = file.read()
        signature = sign_data(file_data, user_private_key)
        
        timestamp = time.time()
        signature_info = {
            'signed_by': username,
            'timestamp': timestamp
        }
        
        signed_document = create_signed_document(file_data, signature, signature_info)
        
        return jsonify({
            'success': True,
            'signed_document': signed_document,
            'filename': f"{file.filename}.signed",
            'signed_by': username,
            'timestamp': timestamp
        })
        
    except Exception as e:
        print(f"Error creando documento firmado: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-signed-document', methods=['POST'])
def api_verify_signed_document():
    
    try:
        signed_document_json = request.json.get('signed_document')
        if not signed_document_json:
            return jsonify({'error': 'No se proporcionó documento firmado'}), 400
        
        original_data, signature, metadata = extract_from_signed_document(signed_document_json)
        signed_by = metadata['signed_by']
        
        _, signer_public_key = get_user_keys(signed_by)
        if not signer_public_key:
            return jsonify({'error': f'No se encontró clave pública para {signed_by}'}), 404
        
        is_valid = verify_signature(original_data, signature, signer_public_key)
        
        return jsonify({
            'valid': is_valid,
            'signed_by': signed_by,
            'timestamp': metadata['timestamp'],
            'filename_reconstructed': f"documento_verificado_{signed_by}",
            'verification_time': time.time()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/verify-simple', methods=['POST'])
def api_verify_simple():
    
    try:
        if 'signed_file' not in request.files:
            return jsonify({'error': 'No se proporcionó archivo firmado'}), 400
        
        file = request.files['signed_file']
        if file.filename == '':
            return jsonify({'error': 'Nombre de archivo vacío'}), 400
        
        if file.filename.endswith('.signed'):
            
            signed_document_json = file.read().decode('utf-8')
            original_data, signature, metadata = extract_from_signed_document(signed_document_json)
            signed_by = metadata['signed_by']
            
            _, signer_public_key = get_user_keys(signed_by)
            if not signer_public_key:
                return jsonify({'error': f'No se encontró usuario: {signed_by}'}), 404
            
            is_valid = verify_signature(original_data, signature, signer_public_key)
            
            return jsonify({
                'valid': is_valid,
                'signed_by': signed_by,
                'timestamp': metadata['timestamp'],
                'file_type': 'signed_document',
                'message': 'Documento firmado VERIFICADO' if is_valid else 'Firma INVALIDA'
            })
            
        else:
            
            file_data = file.read()
            signature = request.form.get('signature', '')
            signed_by = request.form.get('signed_by', '')
            
            if not signature or not signed_by:
                return jsonify({'error': 'Para archivos normales, se requiere firma y firmante'}), 400
            
            _, signer_public_key = get_user_keys(signed_by)
            if not signer_public_key:
                return jsonify({'error': f'No se encontró usuario: {signed_by}'}), 404
            
            is_valid = verify_signature(file_data, signature, signer_public_key)
            
            return jsonify({
                'valid': is_valid,
                'signed_by': signed_by,
                'file_type': 'regular_file',
                'message': 'Firma VERIFICADA' if is_valid else 'Firma INVALIDA'
            })
        
    except Exception as e:
        print(f"Error en verificación simple: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/manual-sign', methods=['POST'])
def api_manual_sign():
    
    try:
        
        private_key_pem = request.form.get('private_key', '').strip()
        
        if 'file' not in request.files:
            return jsonify({'error': 'No se proporcionó archivo'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nombre de archivo vacío'}), 400
        
        if not private_key_pem:
            return jsonify({'error': 'No se proporcionó clave privada'}), 400
        
        try:
            from Crypto.PublicKey import RSA
            private_key = RSA.import_key(private_key_pem)
        except Exception:
            return jsonify({'error': 'Error en la firma'}), 400
        
        file_data = file.read()
        
        try:
            signature = sign_data(file_data, private_key)
        except Exception:
            return jsonify({'error': 'Error en la firma'}), 400
        
        return jsonify({
            'success': True,
            'signature': signature,
            'filename': file.filename
        })
        
    except Exception as e:
        print(f"Error en firma manual: {e}")
        return jsonify({'error': 'Error en la firma'}), 500

@app.route('/api/manual-verify', methods=['POST'])
def api_manual_verify():
    
    try:
    
        public_key_pem = request.form.get('public_key', '').strip()
        signature = request.form.get('signature', '').strip()
        
        if 'file' not in request.files:
            return jsonify({'error': 'Error en verificación'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Error en verificación'}), 400
        
        if not public_key_pem or not signature:
            return jsonify({'error': 'Error en verificación'}), 400
        
        try:
            from Crypto.PublicKey import RSA
            public_key = RSA.import_key(public_key_pem)
        except Exception:
            return jsonify({'error': 'Error en verificación'}), 400
        
        file_data = file.read()
        
        try:
            is_valid = verify_signature(file_data, signature, public_key)
        except Exception:
            return jsonify({'error': 'Error en verificación'}), 400
        
        if is_valid:
            return jsonify({
                'success': True,
                'valid': True,
                'message': 'VERIFICACIÓN EXITOSA'
            })
        else:
            return jsonify({
                'success': True, 
                'valid': False,
                'message': 'ERROR EN VERIFICACIÓN'
            })
        
    except Exception as e:
        print(f"Error en verificación manual: {e}")
        return jsonify({'error': 'Error en verificación'}), 500

if __name__ == '__main__':
    print("=" * 50)
    print(f"Host: {HOST_URL}:{HOST_PORT}")
    print("=" * 50)
    socketio.run(app, host=HOST_URL, port=HOST_PORT, debug=True)