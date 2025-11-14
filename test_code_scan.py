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


# ========== CRITICAL VULNERABILITIES BELOW ==========

@app.route('/api/rce', methods=['POST'])
def remote_code_execution():
    """CRITICAL: Remote Code Execution via compile() and exec()"""
    code = request.json.get('code', '')
    
    # CRITICAL: Compiling and executing user-provided code
    compiled_code = compile(code, '<string>', 'exec')
    exec(compiled_code)
    
    return jsonify({"status": "executed"})


@app.route('/api/xxe', methods=['POST'])
def xml_external_entity():
    """CRITICAL: XML External Entity (XXE) Injection"""
    import xml.etree.ElementTree as ET
    from xml.dom import minidom
    
    xml_data = request.data
    
    # CRITICAL: Parsing XML without disabling external entities
    doc = minidom.parseString(xml_data)
    return doc.toxml()


@app.route('/api/ssrf')
def server_side_request_forgery():
    """CRITICAL: Server-Side Request Forgery"""
    url = request.args.get('url', '')
    
    import urllib.request
    import socket
    
    # CRITICAL: Fetching arbitrary URLs without validation
    response = urllib.request.urlopen(url, timeout=10)
    
    # CRITICAL: Also vulnerable to internal network access
    socket.gethostbyname(url)
    
    return response.read().decode('utf-8')


@app.route('/api/pickle', methods=['POST'])
def insecure_pickle_deserialize():
    """CRITICAL: Insecure Pickle Deserialization"""
    import pickle
    import base64
    
    data = request.json.get('data', '')
    
    # CRITICAL: Pickle can execute arbitrary code during deserialization
    decoded = base64.b64decode(data)
    obj = pickle.loads(decoded)
    
    return jsonify({"deserialized": str(obj)})


@app.route('/api/marshal', methods=['POST'])
def insecure_marshal_deserialize():
    """CRITICAL: Insecure Marshal Deserialization"""
    import marshal
    
    data = request.data
    
    # CRITICAL: Marshal can deserialize arbitrary code objects
    code_obj = marshal.loads(data)
    exec(code_obj)
    
    return jsonify({"status": "executed"})


@app.route('/api/idor/<resource_id>')
def insecure_direct_object_reference(resource_id):
    """CRITICAL: Insecure Direct Object Reference (IDOR)"""
    user_id = session.get('user_id', None)
    
    # CRITICAL: No authorization check - users can access any resource
    conn = psycopg2.connect(
        host="localhost",
        database="app_db",
        user="app_user",
        password=ADMIN_PASSWORD
    )
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM resources WHERE id = {resource_id}")
    result = cur.fetchone()
    conn.close()
    
    return jsonify(result)


@app.route('/api/mass_assignment', methods=['POST'])
def mass_assignment():
    """CRITICAL: Mass Assignment vulnerability"""
    data = request.get_json()
    
    # CRITICAL: Direct assignment of all user data without whitelisting
    user = {}
    user.update(data)  # Allows setting any field including 'is_admin'
    
    # CRITICAL: Saving user with potentially elevated privileges
    conn = psycopg2.connect(
        host="localhost",
        database="app_db",
        user="app_user",
        password=ADMIN_PASSWORD
    )
    cur = conn.cursor()
    cur.execute(f"UPDATE users SET {', '.join([f'{k}={v}' for k, v in user.items()])}")
    conn.commit()
    conn.close()
    
    return jsonify({"updated": True})


@app.route('/api/weak_random')
def weak_random_generation():
    """CRITICAL: Weak Random Number Generation"""
    import random
    import time
    
    # CRITICAL: Using predictable random seed
    random.seed(int(time.time()))
    token = random.randint(100000, 999999)
    
    # CRITICAL: Using weak random for cryptographic purposes
    password = ''.join([chr(random.randint(65, 90)) for _ in range(8)])
    
    return jsonify({"token": token, "password": password})


@app.route('/api/weak_hash')
def weak_hash_algorithm():
    """CRITICAL: Weak Hash Algorithm (SHA1)"""
    import hashlib
    
    password = request.args.get('password', '')
    
    # CRITICAL: SHA1 is cryptographically broken
    hash_value = hashlib.sha1(password.encode()).hexdigest()
    
    return jsonify({"hash": hash_value})


@app.route('/api/weak_crypto')
def weak_cryptography():
    """CRITICAL: Weak Cryptographic Algorithm (DES)"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    
    plaintext = request.args.get('data', '').encode()
    
    # CRITICAL: DES is cryptographically weak (56-bit key)
    key = b"12345678"  # 8 bytes for DES
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext.hex()


@app.route('/api/file_write', methods=['POST'])
def insecure_file_write():
    """CRITICAL: Insecure File Write Operation"""
    filename = request.json.get('filename', '')
    content = request.json.get('content', '')
    
    # CRITICAL: Writing files without path validation or access control
    with open(f"/tmp/{filename}", 'w') as f:
        f.write(content)
    
    # CRITICAL: Also allows overwriting system files
    with open(f"/var/www/{filename}", 'w') as f:
        f.write(content)
    
    return jsonify({"written": True})


@app.route('/api/race_condition')
def race_condition():
    """CRITICAL: Race Condition in File Operations"""
    import os
    
    filename = request.args.get('file', '')
    
    # CRITICAL: Time-of-check to time-of-use (TOCTOU) vulnerability
    if os.path.exists(filename):
        # Race condition: file could be deleted/modified here
        with open(filename, 'r') as f:
            return f.read()
    
    return jsonify({"error": "file not found"})


@app.route('/api/insecure_redirect')
def insecure_redirect():
    """CRITICAL: Insecure Redirect without validation"""
    next_url = request.args.get('next', '')
    
    # CRITICAL: Redirecting to unvalidated URL - allows phishing
    return redirect(next_url)


@app.route('/api/info_disclosure')
def information_disclosure():
    """CRITICAL: Information Disclosure"""
    error = request.args.get('error', '')
    
    # CRITICAL: Exposing sensitive error information
    try:
        raise Exception(f"Database error: {error}")
    except Exception as e:
        # CRITICAL: Revealing stack traces and internal details
        import traceback
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc(),
            "database_password": ADMIN_PASSWORD,
            "secret_key": SECRET_TOKEN
        })


@app.route('/api/insecure_session')
def insecure_session_management():
    """CRITICAL: Insecure Session Management"""
    user_id = request.args.get('user_id', '')
    
    # CRITICAL: Session fixation - accepting user-provided session ID
    session['user_id'] = user_id
    session['authenticated'] = True
    
    # CRITICAL: Long-lived sessions without timeout
    session.permanent = True
    
    return jsonify({"session_id": session.sid})


@app.route('/api/csrf', methods=['POST'])
def csrf_vulnerability():
    """CRITICAL: Missing CSRF Protection"""
    # CRITICAL: No CSRF token validation
    action = request.json.get('action', '')
    amount = request.json.get('amount', 0)
    
    # CRITICAL: Performing sensitive action without CSRF check
    if action == 'transfer':
        # Transfer money without CSRF protection
        return jsonify({"transferred": amount})
    
    return jsonify({"status": "processed"})


@app.route('/api/insecure_api_key')
def insecure_api_key():
    """CRITICAL: Insecure API Key Handling"""
    api_key = request.headers.get('X-API-Key', '')
    
    # CRITICAL: Hardcoded API key comparison
    if api_key == "hardcoded-api-key-12345":
        return jsonify({"authorized": True, "admin": True})
    
    # CRITICAL: API key in URL parameters (logged in access logs)
    api_key_param = request.args.get('api_key', '')
    if api_key_param == SECRET_TOKEN:
        return jsonify({"authorized": True})
    
    return jsonify({"authorized": False})


@app.route('/api/buffer_overflow')
def potential_buffer_overflow():
    """CRITICAL: Potential Buffer Overflow"""
    data = request.args.get('data', '')
    
    # CRITICAL: No bounds checking on string operations
    buffer = bytearray(100)
    data_bytes = data.encode('utf-8')
    
    # CRITICAL: Potential buffer overflow if data > 100 bytes
    for i in range(len(data_bytes)):
        buffer[i] = data_bytes[i]
    
    return jsonify({"processed": True})


@app.route('/api/insecure_error_handling')
def insecure_error_handling():
    """CRITICAL: Insecure Error Handling"""
    try:
        # CRITICAL: Catching all exceptions without proper handling
        result = 1 / 0
    except:
        # CRITICAL: Generic exception handling exposes system details
        import sys
        exc_type, exc_value, exc_traceback = sys.exc_info()
        return jsonify({
            "error": str(exc_value),
            "type": str(exc_type),
            "traceback": str(exc_traceback),
            "system_path": sys.path
        })


@app.route('/api/insecure_logging')
def insecure_logging():
    """CRITICAL: Insecure Logging of Sensitive Data"""
    import logging
    
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    credit_card = request.json.get('credit_card', '')
    
    # CRITICAL: Logging sensitive information
    logging.info(f"User login attempt: username={username}, password={password}")
    logging.debug(f"Credit card number: {credit_card}")
    logging.error(f"Database connection failed with password: {ADMIN_PASSWORD}")
    
    return jsonify({"logged": True})


@app.route('/api/insecure_config')
def insecure_configuration():
    """CRITICAL: Insecure Configuration"""
    # CRITICAL: Debug mode enabled in production
    app.config['DEBUG'] = True
    
    # CRITICAL: Weak session configuration
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = 31536000  # 1 year - too long
    
    # CRITICAL: Exposing internal configuration
    return jsonify({
        "config": app.config,
        "secret_key": app.config.get('SECRET_KEY'),
        "debug": app.config.get('DEBUG')
    })


if __name__ == '__main__':
    # Vulnerable: Running without HTTPS and debug mode
    app.config['SECRET_KEY'] = SECRET_TOKEN
    app.run(host='0.0.0.0', port=8080, debug=True)
