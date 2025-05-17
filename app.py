from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, send_from_directory, flash
from flask_session import Session
from flask_dance.contrib.google import make_google_blueprint, google
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from PIL import Image, ExifTags

import authlib
import dns.resolver
import mimetypes
import requests
import json
import os
import hashlib
import socket
import chardet
import PyPDF2
import re

load_dotenv()



app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # only for local testing

google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
    redirect_to="dashboard",  # or whichever route to go to after login
    scope=["profile", "email"]
)
app.register_blueprint(google_bp, url_prefix="/login")


app.config['SERVER_NAME'] = 'mycyberlab-production.up.railway.app'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'jbierowiec3@gmail.com'
app.config['MAIL_PASSWORD'] = 'jrvi dcqc qoyk syby'  # Use App Password, not your Gmail login
app.config['MAIL_DEFAULT_SENDER'] = 'jbierowiec3@gmail.com'

mail = Mail(app)

ADMIN_EMAIL = "jbierowiec3@gmail.com"



UPLOAD_FOLDER = 'uploads'
DOWNLOAD_FOLDER = 'downloads'
HISTORY_FILE = 'file_history.json'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def load_file_history():
    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'w') as f:
            json.dump({}, f)
        return {}
    with open(HISTORY_FILE, 'r') as f:
        return json.load(f)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)





@app.route("/")
def index():
    return render_template("index.html")

from flask import request, jsonify

@app.route('/contact', methods=['POST'])
def contact():
    try:
        data = request.get_json(force=True)
        name = data.get('name')
        email = data.get('email')
        message = data.get('message')

        if not all([name, email, message]):
            return jsonify({'status': 'error', 'message': 'Missing fields'}), 400

        msg = Message(
            subject=f"New Contact Form Submission from {name}",
            recipients=[ADMIN_EMAIL]
        )

        msg.body = f"""
New Contact Submission

Name: {name}
Email: {email}

Message:
{message}
"""

        msg.html = f"""
<div style="font-family: 'Segoe UI', Tahoma, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e1e1e1; border-radius: 8px;">
  <h2 style="color: #333;">📩 New Contact Form Submission</h2>
  <p><strong>Name:</strong> {name}</p>
  <p><strong>Email:</strong> <a href="mailto:{email}">{email}</a></p>
  <div style="margin-top: 20px;">
    <p style="font-weight: bold;">Message:</p>
    <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #007bff; white-space: pre-wrap;">
      {message}
    </div>
  </div>
  <p style="font-size: 14px; color: #999; margin-top: 30px;">This message was sent from the contact form on MyCyberLab.</p>
</div>
"""

        mail.send(msg)
        return jsonify({"status": "success"}), 200

    except Exception as e:
        print("Error:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

'''
@app.route("/dashboard")
def dashboard():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user_info = resp.json()
    return render_template("dashboard.html", user=user_info, show_welcome=True)
'''

@app.route("/dashboard")
def dashboard():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user_info = resp.json()
    session['user'] = {
        'name': user_info['name'],
        'email': user_info['email'],
        'picture': user_info.get('picture', '')
    }

    return render_template("dashboard.html", user=session['user'], show_welcome=True)


'''
@app.route("/login")
def login():
    # Force redirect URI to exactly match the one in Google Cloud
    redirect_uri = "https://mycyberlab-production.up.railway.app/login/google/authorized"
    print(f"[DEBUG] Sending Google redirect URI: {redirect_uri}")
    return google.authorize_redirect(redirect_uri)
'''
    
@app.route("/login/google/authorized")
def authorized():
    token = google.authorize_access_token()
    resp = google.get("/oauth2/v2/userinfo")
    user_info = resp.json()
    return render_template("dashboard.html", user=user_info)

'''
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
'''

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("index"))


@app.route("/ip-info", methods=["GET", "POST"])
def ip_info():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500
    user = resp.json()

    ip_info = None
    if request.method == "POST":
        ip = request.form['ip']
        ip_info = get_ip_info(ip)

    return render_template("ip_info.html", ip_info=ip_info, user=user)

@app.route("/key-logger", methods=["GET"])
def key_logger():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user = resp.json()
    return render_template("key_logger.html", user=user)

@app.route('/download-keylog', methods=['POST'])
def download_keylog():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500
    user = resp.json()

    name = request.form.get('name', 'Unknown')
    title = request.form.get('title', 'No Title')
    message = request.form.get('message', 'No Message')
    keystrokes = request.form.get('keystrokes', '')
    
    os.makedirs('downloads', exist_ok=True)
    filename = 'keylog.txt'
    file_path = os.path.join('downloads', filename)

    with open(file_path, "w") as file:
        file.write(f"Name: {name}\n")
        file.write(f"Title: {title}\n")
        file.write(f"Message: {message}\n")
        file.write(f"Keystrokes: {keystrokes}\n")

    record_user_file(user['email'], filename, 'downloads')

    return send_file(file_path, as_attachment=True)

@app.route("/basic-cipher", methods=["GET", "POST"])
def basic_cipher():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user = resp.json()
    return render_template("basic_cipher.html", user=user)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500
    user = resp.json()
    
    file = request.files['file']
    cipher_type = request.form['cipher']
    shift = int(request.form.get('shift', 0))
    key = request.form.get('key', '')
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        with open(file_path, 'r') as f:
            text = f.read()
        
        record_user_file(user['email'], filename, 'uploads')
        record_user_file(user['email'], f"encrypted_{filename}", 'downloads')

        if cipher_type == 'caesar':
            encrypted_text = caesar_cipher(text, shift)
        elif cipher_type == 'vigenere':
            encrypted_text = vigenere_cipher(text, key)
        
        encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'encrypted_{filename}')
        with open(encrypted_file_path, 'w') as f:
            f.write(encrypted_text)
        
        return send_file(encrypted_file_path, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500
    user = resp.json()
    
    file = request.files['file']
    cipher_type = request.form['cipher']
    shift = int(request.form.get('shift', 0))
    key = request.form.get('key', '')
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        with open(file_path, 'r') as f:
            text = f.read()
            
        record_user_file(user['email'], filename, 'uploads')
        record_user_file(user['email'], f"decrypted_{filename}", 'downloads')
        
        if cipher_type == 'caesar':
            decrypted_text = caesar_cipher(text, -shift)
        elif cipher_type == 'vigenere':
            decrypted_text = vigenere_cipher(text, key, decrypt=True)
        
        decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'decrypted_{filename}')
        with open(decrypted_file_path, 'w') as f:
            f.write(decrypted_text)
        
        return send_file(decrypted_file_path, as_attachment=True)

@app.route('/file-metadata', methods=['GET', 'POST'])
def file_metadata():
    metadata = None
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user = resp.json()

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = file.filename
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            record_user_file(user['email'], filename, 'uploads')
            record_user_file(user['email'], f"{filename}_metadata_report", 'downloads')

            metadata = {
                'Filename': filename,
                'Size (bytes)': os.path.getsize(file_path),
                'MIME Type': mimetypes.guess_type(file_path)[0] or 'Unknown'
            }

            # Hashes
            def compute_hashes(path):
                with open(path, 'rb') as f:
                    data = f.read()
                    return {
                        'MD5': hashlib.md5(data).hexdigest(),
                        'SHA-1': hashlib.sha1(data).hexdigest(),
                        'SHA-256': hashlib.sha256(data).hexdigest(),
                    }
            metadata.update(compute_hashes(file_path))

            # Image metadata
            try:
                with Image.open(file_path) as img:
                    metadata['Image Format'] = img.format
                    metadata['Dimensions'] = f"{img.width} x {img.height}"
                    metadata['Mode'] = img.mode
                    metadata['DPI'] = img.info.get('dpi', 'N/A')

                    if hasattr(img, '_getexif') and img._getexif():
                        exif = {
                            ExifTags.TAGS.get(tag): val
                            for tag, val in img._getexif().items()
                            if tag in ExifTags.TAGS
                        }
                        metadata.update({f"EXIF - {k}": v for k, v in exif.items() if isinstance(k, str)})
            except:
                pass

            # Text or code files
            try:
                with open(file_path, 'rb') as f:
                    raw = f.read()
                    encoding = chardet.detect(raw)['encoding'] or 'utf-8'
                    text = raw.decode(encoding, errors='ignore')
                    metadata['Encoding'] = encoding
                    metadata['Line Count'] = text.count('\n')
                    metadata['Word Count'] = len(text.split())
            except:
                pass

            # PDF metadata
            if file_path.lower().endswith('.pdf'):
                try:
                    with open(file_path, 'rb') as pdf_file:
                        reader = PyPDF2.PdfReader(pdf_file)
                        metadata['PDF Pages'] = len(reader.pages)
                        if reader.metadata:
                            for key, value in reader.metadata.items():
                                metadata[f"PDF Meta - {key}"] = value
                except:
                    pass

    return render_template('file_metadata.html', metadata=metadata, user=user)

@app.route('/uploads')
def view_uploads():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user = resp.json()
    data = load_file_history()
    uploads = data.get(user['email'], {}).get('uploads', [])
    return render_template('uploads.html', uploads=uploads, user=user)

@app.route('/downloads')
def view_downloads():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user = resp.json()
    data = load_file_history()
    downloads = data.get(user['email'], {}).get('downloads', [])
    return render_template('downloads.html', downloads=downloads, user=user)

@app.route('/delete-file', methods=['POST'])
def delete_file():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500
    user = resp.json()

    file_type = request.form.get('file_type')
    filename = request.form.get('filename')

    data = load_file_history()
    user_history = data.get(user['email'], {file_type: []})

    if filename in user_history.get(file_type, []):
        user_history[file_type].remove(filename)

        file_path = os.path.join('uploads', filename)
        if os.path.exists(file_path):
            os.remove(file_path)

    data[user['email']] = user_history
    save_file_history(data)

    flash(f"{filename} removed from your {file_type} history.")
    return redirect(url_for(f"view_{file_type}"))



# === DNS Lookup Tool ===
@app.route('/dns-tool', methods=['GET', 'POST'])
def dns_tool():
    result = {}
    
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user = resp.json()
    
    if request.method == 'POST':
        domain = request.form['domain']
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                result[rtype] = [str(rdata) for rdata in answers]
            except Exception as e:
                result[rtype] = [f'Error: {e}']
    return render_template('dns_tool.html', result=result, user=user)


# === XSS Demo Tester ===
@app.route('/xss-tester', methods=['GET', 'POST'])
def xss_tester():
    output = ""
    
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user = resp.json()
    
    if request.method == 'POST':
        output = request.form.get('xss_input', '')
    return render_template('xss_tester.html', output=output, user=user)

# === Password Strength Checker ===
@app.route('/password-strength', methods=['GET', 'POST'])
def password_strength():
    feedback = ""
    
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user = resp.json()
    
    if request.method == 'POST':
        pw = request.form['password']
        score = sum([
            len(pw) >= 8,
            any(c.islower() for c in pw),
            any(c.isupper() for c in pw),
            any(c.isdigit() for c in pw),
            any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/' for c in pw)
        ])
        feedback = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"][score]
    return render_template('password_strength.html', feedback=feedback, user=user)

# === Port Scanner Simulation ===
@app.route('/port-scan', methods=['GET', 'POST'])
def port_scan():
    import random
    import time

    port_groups = {
        'Web': [80, 443],
        'Admin': [22, 23],
        'FTP': [21],
        'Email': [25, 110],
        'Database': [3306, 5432]
    }

    results = {}
    risk_level = 'Low'

    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user = resp.json()

    if request.method == 'POST':
        domain = request.form['domain']
        for category, ports in port_groups.items():
            results[category] = []
            for port in ports:
                time.sleep(0.1)  # simulate scan delay
                status = 'open' if port in [80, 443, 22] else 'closed'
                latency = round(random.uniform(10, 100), 2)  # ms
                results[category].append({'port': port, 'status': status, 'latency': latency})

        # Basic risk logic
        open_ports = [p['port'] for group in results.values() for p in group if p['status'] == 'open']
        if 22 in open_ports or 23 in open_ports:
            risk_level = 'Medium'
        if any(p in open_ports for p in [3306, 5432]):
            risk_level = 'High'

    return render_template('port_scan.html', results=results, user=user, risk=risk_level)


# === Hash Generator & Verifier ===
@app.route('/hash-tool', methods=['GET', 'POST'])
def hash_tool():
    import hashlib
    result = {}
    verified = None
    text_input = ''
    uploaded_filename = None

    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user = resp.json()

    if request.method == 'POST':
        text_input = request.form.get('data', '')
        uploaded_file = request.files.get('file')
        compare_hash = request.form.get('compare_hash', '').strip()

        if uploaded_file and uploaded_file.filename != '':
            content = uploaded_file.read()
            uploaded_filename = uploaded_file.filename
        else:
            content = text_input.encode()

        hashes = {
            'MD5': hashlib.md5(content).hexdigest(),
            'SHA-1': hashlib.sha1(content).hexdigest(),
            'SHA-256': hashlib.sha256(content).hexdigest(),
        }

        result = hashes

        if compare_hash:
            verified = compare_hash in hashes.values()

    return render_template(
        'hash_tool.html',
        result=result,
        verified=verified,
        user=user,
        text_input=text_input,
        uploaded_filename=uploaded_filename
    )

@app.route('/password-cracker')
def password_cracker():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500
    user = resp.json()
    
    return render_template('password_cracker.html', user=user)

@app.route('/save-log', methods=['POST'])
def save_log():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return "Failed to fetch user info", 500
    user = resp.json()
    email = user['email']

    data = request.get_json()
    csv_content = data.get("csv")
    password = data.get("password")  # Password must also be sent in request

    if not csv_content or not password:
        return "Missing CSV content or password", 400

    # Sanitize password and build filename
    safe_password = re.sub(r'[^a-zA-Z0-9_-]', '_', password)
    filename = f"{safe_password}_crack_attempts.csv"

    file_path = os.path.join("downloads", filename)
    with open(file_path, "w") as f:
        f.write(csv_content)

    record_user_file(email, filename, "downloads")
    return {"message": "Saved successfully"}





def load_file_history():
    if not os.path.exists(HISTORY_FILE):
        return {}
    with open(HISTORY_FILE, 'r') as f:
        return json.load(f)

def save_file_history(data):
    with open(HISTORY_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def record_user_file(email, file_name, file_type):
    data = load_file_history()
    if email not in data:
        data[email] = {'uploads': [], 'downloads': []}
    if file_name not in data[email][file_type]:
        data[email][file_type].append(file_name)
    save_file_history(data)

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            new_char = chr(((ord(char.lower()) - ord('a') + shift_amount) % 26) + ord('a'))
            result += new_char.upper() if char.isupper() else new_char
        else:
            result += char
    return result

def vigenere_cipher(text, key, decrypt=False):
    result = ""
    key = key.lower()
    key_index = 0
    key_length = len(key)
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % key_length]) - ord('a')
            if decrypt:
                shift = -shift
            new_char = chr(((ord(char.lower()) - ord('a') + shift) % 26) + ord('a'))
            result += new_char.upper() if char.isupper() else new_char
            key_index += 1
        else:
            result += char
    return result

def get_ip_info(ip):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url)
    data = response.json()
    return data if data["status"] != "fail" else None

if __name__ == '__main__':
    app.run(debug=True)



# OWASP ZAP -> website for seeing how well your website is secured
# I'll ask bout the the youtube videos & the slides he showed up
# OWASP Top 10 certification