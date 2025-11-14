"""
CodeQL Security Scanning Test File
Contains various security vulnerabilities for testing CodeQL detection
"""

import json
import yaml
import re
import shlex
import subprocess
from flask import Flask, request, jsonify, session, redirect
import psycopg2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Hardcoded secrets and credentials
SECRET_TOKEN = "production-secret-abc123xyz789"
ENCRYPTION_KEY = b"1234567890123456"  # 16 bytes but weak
ADMIN_PASSWORD = "Changeme123!"


@app.route('/api/users/<user_id>')
def get_user_profile(user_id):
    """SQL Injection using f-string formatting"""
    conn = psycopg2.connect(
        host="localhost",
        database="app_db",
        user="app_user",
        password=ADMIN_PASSWORD
    )
    cur = conn.cursor()
    
    # Vulnerable: f-string SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cur.execute(query)
    
    result = cur.fetchone()
    conn.close()
    return jsonify(result)


@app.route('/api/process')
def process_data():
    """Command Injection using shlex.split incorrectly"""
    user_input = request.args.get('input', '')
    
    # Vulnerable: Using shlex.split but still unsafe with shell commands
    cmd = f"echo {user_input} | base64"
    result = subprocess.check_output(cmd, shell=True)
    
    return result.decode('utf-8')


@app.route('/api/parse_json', methods=['POST'])
def parse_json_data():
    """JSON Injection / Deserialization vulnerability"""
    data = request.get_json()
    
    # Vulnerable: Direct JSON parsing without validation
    user_data = json.loads(request.data)
    
    # Vulnerable: Using eval with JSON data
    if 'expression' in user_data:
        result = eval(user_data['expression'])
        return jsonify({"result": result})
    
    return jsonify(user_data)


@app.route('/api/load_yaml', methods=['POST'])
def load_yaml_config():
    """YAML Deserialization vulnerability"""
    yaml_content = request.data.decode('utf-8')
    
    # Vulnerable: Using yaml.load instead of yaml.safe_load
    config = yaml.load(yaml_content, Loader=yaml.Loader)
    
    return jsonify(config)


@app.route('/api/regex')
def regex_processing():
    """ReDoS (Regular Expression Denial of Service) vulnerability"""
    pattern = request.args.get('pattern', '')
    text = request.args.get('text', '')
    
    # Vulnerable: User-controlled regex pattern can cause ReDoS
    match = re.search(pattern, text)
    
    if match:
        return jsonify({"found": match.group()})
    return jsonify({"found": None})


@app.route('/api/encrypt')
def encrypt_data():
    """Weak encryption implementation"""
    plaintext = request.args.get('data', '').encode()
    
    # Vulnerable: Using weak ECB mode and hardcoded key
    cipher = Cipher(
        algorithms.AES(ENCRYPTION_KEY),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext.hex()


@app.route('/api/authenticate', methods=['POST'])
def authenticate_user():
    """Weak authentication with hardcoded comparison"""
    credentials = request.get_json()
    username = credentials.get('username', '')
    password = credentials.get('password', '')
    
    # Vulnerable: Timing attack - string comparison
    if username == "admin" and password == ADMIN_PASSWORD:
        session['authenticated'] = True
        session['user'] = username
        return jsonify({"status": "authenticated"})
    
    return jsonify({"status": "failed"}), 401


@app.route('/api/search')
def search_functionality():
    """LDAP Injection vulnerability"""
    search_term = request.args.get('q', '')
    
    import ldap
    ldap_conn = ldap.initialize('ldap://ldap.example.com')
    
    # Vulnerable: LDAP injection with string formatting
    search_filter = "(cn={})".format(search_term)
    results = ldap_conn.search_s(
        'dc=example,dc=com',
        ldap.SCOPE_SUBTREE,
        search_filter
    )
    
    return jsonify({"results": results})


@app.route('/api/export')
def export_data():
    """Path Traversal in file operations"""
    filename = request.args.get('file', 'report.pdf')
    
    # Vulnerable: No path sanitization
    file_path = f"/exports/{filename}"
    
    with open(file_path, 'rb') as f:
        return f.read()


@app.route('/api/webhook')
def webhook_handler():
    """Insecure webhook processing"""
    payload = request.get_json()
    
    # Vulnerable: Executing commands from webhook payload
    if 'command' in payload:
        cmd = payload['command']
        output = subprocess.run(cmd, shell=True, capture_output=True)
        return jsonify({"output": output.stdout.decode()})
    
    return jsonify({"status": "processed"})


def generate_session_token():
    """Weak session token generation"""
    import random
    import string
    
    # Vulnerable: Using random instead of secrets module
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return token


@app.route('/api/session')
def create_session():
    """Insecure session management"""
    token = generate_session_token()
    
    # Vulnerable: Session token in URL parameter
    return redirect(f"/dashboard?token={token}")


@app.route('/api/validate')
def validate_input():
    """Insufficient input validation"""
    email = request.args.get('email', '')
    
    # Vulnerable: Weak email validation
    if '@' in email:
        return jsonify({"valid": True})
    
    return jsonify({"valid": False})


@app.route('/api/headers')
def check_headers():
    """Insecure header processing"""
    user_agent = request.headers.get('User-Agent', '')
    
    # Vulnerable: Trusting User-Agent header
    if 'admin' in user_agent.lower():
        return jsonify({"admin": True})
    
    return jsonify({"admin": False})


@app.route('/api/cors')
def cors_endpoint():
    """Insecure CORS configuration"""
    from flask_cors import cross_origin
    
    # Vulnerable: Allowing all origins
    response = jsonify({"data": "sensitive information"})
    response.headers['Access-Control-Allow-Origin'] = '*'
    
    return response


if __name__ == '__main__':
    # Vulnerable: Running without HTTPS and debug mode
    app.config['SECRET_KEY'] = SECRET_TOKEN
    app.run(host='0.0.0.0', port=8080, debug=True)
