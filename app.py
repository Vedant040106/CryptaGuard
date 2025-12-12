import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config
import feedparser
import requests
import hashlib
from stego_engine import StegoModule

# Initialize the Steganography Tool
stego_tool = StegoModule()

app = Flask(__name__)
app.config.from_object(Config)

# --- ABSOLUTE PATH CONFIGURATION ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- DATABASE CONNECTION ---
def get_db_connection():
    try:
        return mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
    except Exception as e:
        print(f"DATABASE ERROR: {e}")
        return None

# --- HELPER: LOG ACTIVITY ---
def log_activity(module, action, status):
    if 'user_id' not in session: return
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO activity_logs (user_id, module, action, status) VALUES (%s, %s, %s, %s)",
                       (session['user_id'], module, action, status))
        conn.commit()
        conn.close()

# ==========================================
#              CORE ROUTES
# ==========================================


# 1. Landing Page (Always the entry point)
@app.route('/')
def landing_page():
    return render_template('landing.html')

# 2. The Dashboard (Now Publicly Accessible)
@app.route('/dashboard')
def dashboard():
    # Check if user is logged in, but DO NOT redirect if they aren't.
    if 'user_id' in session:
        return render_template('index.html', username=session.get('username'), logged_in=True)
    else:
        # Serve as Guest
        return render_template('index.html', username='Guest Agent', logged_in=False)
# 3. Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            log_activity('System', 'User Logged In', 'Success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

# 4. Register (RESTORED)
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    hashed_pw = generate_password_hash(password)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)", 
                       (username, email, hashed_pw))
        conn.commit()
        conn.close()
        flash('Registration successful!', 'success')
    except:
        flash('User already exists.', 'error')
    return redirect(url_for('login'))

# 5. Logout (RESTORED - Fixes the Crash)
@app.route('/logout')
def logout():
    log_activity('System', 'User Logged Out', 'Success')
    session.clear()
    return redirect(url_for('login'))


# ==========================================
#              API ENDPOINTS
# ==========================================

# --- MALWARE SANDBOX ENGINE (HASHING + EICAR) ---
@app.route('/api/upload_scan', methods=['POST'])
def upload_scan():
    if 'file' not in request.files: return jsonify({'error': 'No file'})
    file = request.files['file']
    scan_type = request.form.get('type', 'Unknown')
    
    if file.filename == '': return jsonify({'error': 'No filename'})
    
    # 1. Secure Save
    filename = secure_filename(file.filename)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(save_path)
    
    # 2. Cryptographic Hashing (SHA-256)
    sha256_hash = hashlib.sha256()
    with open(save_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    # 3. Threat Analysis
    status = 'SAFE'
    threat_level = 'Low'
    flags = []

    # Check A: Dangerous Extensions
    if filename.lower().endswith(('.exe', '.bat', '.vbs', '.scr', '.cmd', '.sh')):
        status = 'SUSPICIOUS'
        threat_level = 'Medium'
        flags.append('Executable Content')

    # Check B: EICAR Test String
    eicar_hash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
    if file_hash == eicar_hash:
        status = 'THREAT DETECTED'
        threat_level = 'Critical'
        flags.append('EICAR Test Signature')

    # Logging
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO stored_files (user_id, filename, file_type, file_path) VALUES (%s, %s, %s, %s)",
                   (session['user_id'], filename, scan_type, filename))
    conn.commit()
    conn.close()
    
    log_activity('File Scanner', f'Scanned {filename} [{status}]', status)
    
    return jsonify({
        'status': status, 
        'filename': filename,
        'hash': file_hash,
        'threat_level': threat_level,
        'flags': flags
    })

# --- DOWNLOAD ROUTE ---
@app.route('/uploads/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- STEGANOGRAPHY ROUTES ---
@app.route('/api/stego/encode', methods=['POST'])
def stego_encode():
    if 'file' not in request.files: return jsonify({'error': 'No file'})
    file = request.files['file']
    message = request.form.get('message', '')
    
    if not message: return jsonify({'error': 'Message required'})
    
    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + filename)
    
    name_without_ext = os.path.splitext(filename)[0]
    output_filename = 'encoded_' + name_without_ext + '.png'
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
    
    file.save(input_path)
    try:
        stego_tool.encode(input_path, message, output_path)
        if os.path.exists(input_path): os.remove(input_path) 
        log_activity('Stego Lab', f'Encoded data into {filename}', 'Success')
        return jsonify({'status': 'success', 'filename': output_filename})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/stego/decode', methods=['POST'])
def stego_decode():
    if 'file' not in request.files: return jsonify({'error': 'No file'})
    file = request.files['file']
    filename = secure_filename(file.filename)
    scan_path = os.path.join(app.config['UPLOAD_FOLDER'], 'scan_' + filename)
    file.save(scan_path)
    try:
        detected, content = stego_tool.decode(scan_path)
        if os.path.exists(scan_path): os.remove(scan_path)
        status = 'DETECTED' if detected else 'CLEAN'
        log_activity('Stego Lab', f'Decoded {filename}: {status}', 'Success')
        return jsonify({'detected': detected, 'message': content})
    except Exception as e:
        return jsonify({'error': str(e)})

# --- REAL-TIME DYNAMIC URL ANALYZER ---
@app.route('/api/url_checker', methods=['POST'])
def url_checker():
    try:
        data = request.json
        url = data.get('url', '')
        if not url: return jsonify({'status': 'error', 'message': 'Empty URL'})

        target = url if url.startswith(('http://', 'https://')) else 'http://' + url
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

        response = requests.get(target, headers=headers, timeout=5, allow_redirects=True)
        
        if 200 <= response.status_code < 300:
            return jsonify({
                'status': 'online',
                'final_url': response.url,
                'content_type': response.headers.get('Content-Type', '')
            })
        else:
            return jsonify({'status': 'online', 'final_url': target})
    except requests.ConnectionError:
        return jsonify({'status': 'offline'})
    except Exception as e:
        return jsonify({'status': 'offline'})

# --- NEWS & CHAT APIs ---
@app.route('/api/cyber_news')
def cyber_news():
    try:
        feed = feedparser.parse("https://feeds.feedburner.com/TheHackersNews")
        news_items = [{'title': e.title, 'link': e.link, 'published': e.published} for e in feed.entries[:5]]
        return jsonify(news_items)
    except: return jsonify([])

@app.route('/api/search_user', methods=['POST'])
def search_user():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username FROM users WHERE username = %s AND id != %s", (data['username'], session['user_id']))
    user = cursor.fetchone()
    conn.close()
    return jsonify({'found': bool(user), 'user': user})

@app.route('/api/add_friend', methods=['POST'])
def add_friend():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM friend_requests WHERE (sender_id=%s AND receiver_id=%s) OR (sender_id=%s AND receiver_id=%s)", 
                   (session['user_id'], data['friend_id'], data['friend_id'], session['user_id']))
    if cursor.fetchone():
        conn.close()
        return jsonify({'status': 'exists'})
    cursor.execute("INSERT INTO friend_requests (sender_id, receiver_id) VALUES (%s, %s)", (session['user_id'], data['friend_id']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sent'})

@app.route('/api/get_requests', methods=['GET'])
def get_requests():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT r.id, u.username, r.sender_id, 'incoming' as type FROM friend_requests r JOIN users u ON r.sender_id = u.id WHERE r.receiver_id = %s AND r.status = 'pending'", (session['user_id'],))
    incoming = cursor.fetchall()
    cursor.execute("SELECT r.id, u.username, r.receiver_id, 'outgoing' as type FROM friend_requests r JOIN users u ON r.receiver_id = u.id WHERE r.sender_id = %s AND r.status = 'pending'", (session['user_id'],))
    outgoing = cursor.fetchall()
    conn.close()
    return jsonify(incoming + outgoing)

@app.route('/api/accept_request', methods=['POST'])
def accept_request():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE friend_requests SET status = 'accepted' WHERE id = %s", (data['request_id'],))
    conn.commit()
    conn.close()
    return jsonify({'status': 'accepted'})

@app.route('/api/get_friends', methods=['GET'])
def get_friends():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT u.id, u.username FROM friend_requests r JOIN users u ON (u.id = r.sender_id OR u.id = r.receiver_id) WHERE (r.sender_id = %s OR r.receiver_id = %s) AND r.status = 'accepted' AND u.id != %s", (user_id, user_id, user_id))
    friends = cursor.fetchall()
    conn.close()
    return jsonify(friends)

@app.route('/api/send_message', methods=['POST'])
def send_message():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender_id, receiver_id, message_content) VALUES (%s, %s, %s)", (session['user_id'], data['receiver_id'], data['content']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sent'})

@app.route('/api/get_messages', methods=['POST'])
def get_messages():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, sender_id, receiver_id, message_content, CAST(timestamp AS CHAR) as timestamp FROM messages WHERE (sender_id=%s AND receiver_id=%s) OR (sender_id=%s AND receiver_id=%s) ORDER BY timestamp ASC", (session['user_id'], data['friend_id'], data['friend_id'], session['user_id']))
    messages = cursor.fetchall()
    conn.close()
    return jsonify(messages)

@app.route('/api/get_history', methods=['GET'])
def get_history():
    if 'user_id' not in session: return jsonify([])
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT module, action, status, CAST(timestamp AS CHAR) as timestamp FROM activity_logs WHERE user_id = %s ORDER BY timestamp DESC LIMIT 50", (session['user_id'],))
    logs = cursor.fetchall()
    conn.close()
    return jsonify(logs)

@app.route('/api/log_tool', methods=['POST'])
def log_tool():
    data = request.json
    log_activity(data['module'], data['action'], data['status'])
    return jsonify({'status': 'logged'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)