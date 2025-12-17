"""
CodeQL Code Scanning Vulnerabilities Test File
This file contains intentional code vulnerabilities for CodeQL code scanning
Focuses on code-level vulnerabilities that CodeQL can detect through static analysis
"""

import os
import sys
import json
import re
import base64
import tempfile
import shutil
import subprocess
import sqlite3
import hashlib
import pickle
import yaml
import xml.etree.ElementTree as ET
from flask import Flask, request, session, jsonify, make_response, render_template_string, redirect
from werkzeug.security import generate_password_hash
import jwt
import requests
import urllib.request

app = Flask(__name__)

# Note: This file focuses on code vulnerabilities, not secrets
# CodeQL detects code patterns, not hardcoded secrets (that's secret scanning)


# ============================================================================
# SQL INJECTION VULNERABILITIES
# ============================================================================

@app.route('/api/users')
def get_users():
    """SQL Injection - String concatenation"""
    username = request.args.get('username', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Direct string concatenation in SQL
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


@app.route('/api/user_by_id')
def get_user_by_id():
    """SQL Injection - Format string"""
    user_id = request.args.get('id', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Format string injection
    query = "SELECT * FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


@app.route('/api/user_by_email')
def get_user_by_email():
    """SQL Injection - f-string"""
    email = request.args.get('email', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: f-string with user input
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


@app.route('/api/search')
def search_users():
    """SQL Injection - Multiple parameters"""
    name = request.args.get('name', '')
    role = request.args.get('role', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Multiple user inputs in query
    query = f"SELECT * FROM users WHERE name = '{name}' AND role = '{role}'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


# ============================================================================
# COMMAND INJECTION VULNERABILITIES
# ============================================================================

@app.route('/api/ping')
def ping_host():
    """Command Injection - os.system"""
    host = request.args.get('host', 'localhost')
    
    # Vulnerable: User input directly in os.system
    os.system(f"ping -c 4 {host}")
    
    return jsonify({"status": "ping executed"})


@app.route('/api/list_directory')
def list_directory():
    """Command Injection - subprocess with shell=True"""
    directory = request.args.get('dir', '.')
    
    # Vulnerable: shell=True with user input
    result = subprocess.run(f"ls -la {directory}", shell=True, capture_output=True, text=True)
    
    return result.stdout


@app.route('/api/grep')
def grep_file():
    """Command Injection - subprocess.Popen"""
    pattern = request.args.get('pattern', '')
    filename = request.args.get('file', 'data.txt')
    
    # Vulnerable: User input in command without validation
    process = subprocess.Popen(['grep', pattern, filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    
    return output.decode()


@app.route('/api/execute')
def execute_command():
    """Command Injection - eval with os.system"""
    command = request.args.get('cmd', '')
    
    # Extremely vulnerable: eval can execute arbitrary code
    eval(f"os.system('{command}')")
    
    return jsonify({"status": "command executed"})


@app.route('/api/run_script')
def run_script():
    """Command Injection - exec"""
    script = request.args.get('script', '')
    
    # Extremely vulnerable: exec executes arbitrary code
    exec(script)
    
    return jsonify({"status": "script executed"})


# ============================================================================
# PATH TRAVERSAL VULNERABILITIES
# ============================================================================

@app.route('/api/read_file')
def read_file():
    """Path Traversal - Direct file access"""
    filename = request.args.get('file', 'config.json')
    
    # Vulnerable: No path validation
    with open(f'/etc/config/{filename}', 'r') as f:
        content = f.read()
    
    return content


@app.route('/api/download')
def download_file():
    """Path Traversal - os.path.join without validation"""
    filepath = request.args.get('path', '')
    
    # Vulnerable: User input in file path
    full_path = os.path.join('/var/www/files', filepath)
    
    with open(full_path, 'rb') as f:
        content = f.read()
    
    return content


@app.route('/api/delete')
def delete_file():
    """Path Traversal - File deletion"""
    filename = request.args.get('file', '')
    
    # Vulnerable: No validation before deletion
    filepath = f'/tmp/uploads/{filename}'
    os.remove(filepath)
    
    return jsonify({"status": "file deleted"})


@app.route('/api/copy_file')
def copy_file():
    """Path Traversal - File operations"""
    source = request.args.get('source', '')
    dest = request.args.get('dest', '')
    
    # Vulnerable: No path validation
    shutil.copy(source, dest)
    
    return jsonify({"status": "file copied"})


# ============================================================================
# CODE INJECTION VULNERABILITIES
# ============================================================================

@app.route('/api/eval')
def eval_code():
    """Code Injection - eval()"""
    user_code = request.args.get('code', '')
    
    # Extremely vulnerable: executing arbitrary code
    result = eval(user_code)
    
    return jsonify({"result": str(result)})


@app.route('/api/exec')
def exec_code():
    """Code Injection - exec()"""
    user_code = request.args.get('code', '')
    
    # Extremely vulnerable: executing arbitrary code
    exec(user_code)
    
    return jsonify({"status": "code executed"})


@app.route('/api/compile')
def compile_code():
    """Code Injection - compile() and eval()"""
    user_code = request.args.get('code', '')
    
    # Vulnerable: Compiling and executing user code
    compiled = compile(user_code, '<string>', 'exec')
    eval(compiled)
    
    return jsonify({"status": "code compiled and executed"})


# ============================================================================
# INSECURE DESERIALIZATION
# ============================================================================

@app.route('/api/unpickle', methods=['POST'])
def unpickle_data():
    """Insecure Deserialization - pickle"""
    data = request.get_json().get('data', '')
    
    # Vulnerable: pickle can execute arbitrary code
    decoded = base64.b64decode(data)
    obj = pickle.loads(decoded)
    
    return jsonify({"result": str(obj)})


@app.route('/api/yaml_load', methods=['POST'])
def load_yaml():
    """Insecure Deserialization - yaml.load"""
    yaml_data = request.data
    
    # Vulnerable: yaml.load without safe_load
    data = yaml.load(yaml_data, Loader=yaml.Loader)
    
    return jsonify(data)


@app.route('/api/marshal_load', methods=['POST'])
def marshal_load():
    """Insecure Deserialization - marshal"""
    import marshal
    
    data = request.get_json().get('data', '')
    
    # Vulnerable: marshal can deserialize arbitrary objects
    decoded = base64.b64decode(data)
    obj = marshal.loads(decoded)
    
    return jsonify({"result": str(obj)})


# ============================================================================
# WEAK CRYPTOGRAPHY
# ============================================================================

def hash_password_md5(password):
    """Weak Hash - MD5"""
    # Vulnerable: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password):
    """Weak Hash - SHA1"""
    # Vulnerable: SHA1 is deprecated
    return hashlib.sha1(password.encode()).hexdigest()


def generate_token_insecure():
    """Insecure Random - random module"""
    import random
    
    # Vulnerable: random is not cryptographically secure
    token = ''.join([str(random.randint(0, 9)) for _ in range(32)])
    return token


def generate_session_id():
    """Insecure Random - time-based"""
    import time
    
    # Vulnerable: Predictable session ID
    session_id = str(int(time.time()))
    return session_id


def encrypt_data_weak(data, key):
    """Weak Encryption - ECB mode"""
    # Vulnerable: ECB mode is insecure (code pattern issue, not secret)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    key_bytes = key.encode()[:16] if isinstance(key, str) else key[:16]
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padded_data = data.encode().ljust(16, b' ')
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(ciphertext).decode()


@app.route('/api/hash')
def hash_password():
    """Weak Hash - User input"""
    password = request.args.get('password', '')
    
    # Vulnerable: Using MD5
    hash_value = hashlib.md5(password.encode()).hexdigest()
    
    return jsonify({"hash": hash_value})


# ============================================================================
# SSRF (Server-Side Request Forgery)
# ============================================================================

@app.route('/api/fetch')
def fetch_url():
    """SSRF - urllib"""
    url = request.args.get('url', '')
    
    # Vulnerable: Fetching arbitrary URLs
    response = urllib.request.urlopen(url)
    return response.read()


@app.route('/api/proxy')
def proxy_request():
    """SSRF - requests library"""
    url = request.args.get('url', '')
    
    # Vulnerable: No URL validation
    response = requests.get(url, timeout=5)
    return response.text


@app.route('/api/internal')
def fetch_internal():
    """SSRF - Internal network access"""
    path = request.args.get('path', '')
    
    # Vulnerable: Accessing internal resources
    url = f"http://localhost:8080/api/{path}"
    response = requests.get(url)
    return response.json()


@app.route('/api/webhook')
def webhook():
    """SSRF - Webhook callback"""
    callback_url = request.args.get('callback', '')
    
    # Vulnerable: Making request to user-controlled URL
    requests.post(callback_url, json={"status": "completed"})
    
    return jsonify({"status": "webhook sent"})


# ============================================================================
# XSS (Cross-Site Scripting)
# ============================================================================

@app.route('/api/render')
def render_template():
    """XSS - Template injection"""
    template = request.args.get('template', 'Hello')
    
    # Vulnerable: User input in template
    return render_template_string(template)


@app.route('/api/comment')
def display_comment():
    """XSS - Unsanitized output"""
    comment = request.args.get('comment', '')
    
    # Vulnerable: No HTML escaping
    html = f"<div class='comment'>{comment}</div>"
    return html


@app.route('/api/cookie')
def set_cookie_unsafe():
    """XSS - Cookie manipulation"""
    value = request.args.get('value', '')
    
    # Vulnerable: User input in cookie without sanitization
    resp = make_response("Cookie set")
    resp.set_cookie('user_data', value, httponly=False, secure=False, samesite=None)
    
    return resp


# ============================================================================
# XXE (XML External Entity)
# ============================================================================

@app.route('/api/parse_xml', methods=['POST'])
def parse_xml():
    """XXE - XML parsing without protection"""
    xml_data = request.data
    
    # Vulnerable: No XXE protection
    parser = ET.XMLParser()
    tree = ET.fromstring(xml_data, parser=parser)
    
    return ET.tostring(tree)


@app.route('/api/xml_lxml', methods=['POST'])
def parse_xml_lxml():
    """XXE - lxml parsing"""
    from lxml import etree
    
    xml_data = request.data
    
    # Vulnerable: No XXE protection
    tree = etree.fromstring(xml_data)
    
    return etree.tostring(tree)


# ============================================================================
# LDAP INJECTION
# ============================================================================

def ldap_search(username):
    """LDAP Injection"""
    try:
        import ldap
        
        # Vulnerable: Unsanitized input in LDAP query
        ldap_conn = ldap.initialize('ldap://localhost')
        search_filter = f"(uid={username})"
        
        results = ldap_conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, search_filter)
        return results
    except ImportError:
        return []


@app.route('/api/ldap')
def ldap_query():
    """LDAP Injection endpoint"""
    username = request.args.get('username', '')
    results = ldap_search(username)
    return jsonify({"results": str(results)})


# ============================================================================
# XPATH INJECTION
# ============================================================================

def xpath_search(username):
    """XPath Injection"""
    try:
        from lxml import etree
        
        xml = etree.parse('users.xml')
        
        # Vulnerable: Unsanitized input in XPath
        query = f"//user[username='{username}']"
        result = xml.xpath(query)
        
        return result
    except Exception:
        return []


@app.route('/api/xpath')
def xpath_query():
    """XPath Injection endpoint"""
    username = request.args.get('username', '')
    results = xpath_search(username)
    return jsonify({"results": str(results)})


# ============================================================================
# INSECURE COOKIES
# ============================================================================

@app.route('/api/session')
def set_session():
    """Insecure Cookie - Missing flags"""
    session_id = request.args.get('session_id', '12345')
    
    # Vulnerable: Cookie without secure and httponly flags
    resp = make_response("Session set")
    resp.set_cookie('session', session_id, httponly=False, secure=False, samesite=None)
    
    return resp


@app.route('/api/auth_cookie')
def set_auth_cookie():
    """Insecure Cookie - Sensitive data"""
    auth_token = request.args.get('token', '')
    
    # Vulnerable: Sensitive data in cookie without proper flags
    resp = make_response("Auth cookie set")
    resp.set_cookie('auth_token', auth_token, httponly=False, secure=False)
    
    return resp


# ============================================================================
# INFORMATION DISCLOSURE
# ============================================================================

@app.route('/api/error')
def error_handler():
    """Information Disclosure - Stack traces"""
    try:
        # Vulnerable: Exposing stack traces
        result = 1 / 0
    except Exception as e:
        import traceback
        # Vulnerable: Returning full traceback
        return jsonify({"error": str(traceback.format_exc())})


@app.route('/api/debug')
def debug_info():
    """Information Disclosure - Debug information"""
    # Vulnerable: Exposing system information
    info = {
        'python_version': sys.version,
        'platform': sys.platform,
        'path': sys.path,
        'env': dict(os.environ)
    }
    
    return jsonify(info)


@app.route('/api/version')
def version_info():
    """Information Disclosure - Version information"""
    # Vulnerable: Exposing version details
    return jsonify({
        "version": "1.0.0",
        "build": "20240101",
        "environment": os.environ.get('ENV', 'production')
    })


# ============================================================================
# INSECURE FILE OPERATIONS
# ============================================================================

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Unrestricted File Upload"""
    file = request.files['file']
    
    # Vulnerable: No file type validation
    file.save(f'/var/www/uploads/{file.filename}')
    
    return jsonify({"status": "file uploaded"})


@app.route('/api/temp_file')
def create_temp_file():
    """Insecure Temporary File"""
    filename = request.args.get('filename', 'temp.txt')
    
    # Vulnerable: Predictable temporary file name
    temp_path = f'/tmp/{filename}'
    
    with open(temp_path, 'w') as f:
        f.write('temporary data')
    
    return jsonify({"path": temp_path})


# ============================================================================
# LOG INJECTION
# ============================================================================

@app.route('/api/log')
def log_user_action():
    """Log Injection"""
    import logging
    
    action = request.args.get('action', '')
    user_id = request.args.get('user_id', '')
    
    # Vulnerable: Unsanitized user input in logs
    logging.info(f"User {user_id} performed action: {action}")
    
    return jsonify({"status": "action logged"})


@app.route('/api/audit')
def audit_log():
    """Log Injection - Audit logs"""
    import logging
    
    event = request.args.get('event', '')
    details = request.args.get('details', '')
    
    # Vulnerable: User input in audit logs
    logging.warning(f"Audit event: {event} - Details: {details}")
    
    return jsonify({"status": "audit logged"})


# ============================================================================
# OPEN REDIRECT
# ============================================================================

@app.route('/api/redirect')
def open_redirect():
    """Open Redirect"""
    target = request.args.get('url', '/')
    
    # Vulnerable: Redirecting to unvalidated URL
    return redirect(target)


@app.route('/api/callback')
def callback_redirect():
    """Open Redirect - Callback"""
    return_url = request.args.get('return_url', '/')
    
    # Vulnerable: Unvalidated redirect
    return redirect(return_url)


# ============================================================================
# INSECURE JWT
# ============================================================================

def create_jwt_weak(payload, secret):
    """Insecure JWT - No algorithm validation"""
    # Vulnerable: Code pattern - should validate algorithm
    token = jwt.encode(payload, secret, algorithm='HS256')
    return token


def verify_jwt_weak(token, secret):
    """Insecure JWT - No algorithm specification"""
    # Vulnerable: Algorithm not specified (algorithm confusion attack - code pattern)
    payload = jwt.decode(token, secret)  # Missing algorithms parameter
    return payload


@app.route('/api/jwt/create')
def create_jwt():
    """Insecure JWT endpoint"""
    user_id = request.args.get('user_id', '')
    secret = request.args.get('secret', 'default-secret')  # User-provided, not hardcoded
    payload = {"user_id": user_id, "role": "user"}
    
    token = create_jwt_weak(payload, secret)
    return jsonify({"token": token})


@app.route('/api/jwt/verify')
def verify_jwt_endpoint():
    """Insecure JWT verification - Algorithm confusion"""
    token = request.args.get('token', '')
    secret = request.args.get('secret', 'default-secret')
    
    try:
        # Vulnerable: Missing algorithms parameter allows algorithm confusion
        payload = verify_jwt_weak(token, secret)
        return jsonify({"valid": True, "payload": payload})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})


# ============================================================================
# REGEX INJECTION (ReDoS)
# ============================================================================

def validate_email_regex(email):
    """ReDoS - Vulnerable regex"""
    # Vulnerable: Catastrophic backtracking possible
    pattern = r'^([a-zA-Z0-9_\.-]+)@([\da-zA-Z\.-]+)\.([a-zA-Z\.]{2,6})$'
    
    if re.match(pattern, email):
        return True
    return False


@app.route('/api/validate_email')
def validate_email():
    """ReDoS endpoint"""
    email = request.args.get('email', '')
    is_valid = validate_email_regex(email)
    return jsonify({"valid": is_valid})


# ============================================================================
# INSECURE COMPARISON (Timing Attacks)
# ============================================================================

def check_password_unsafe(input_password, stored_hash):
    """Timing Attack - Insecure comparison"""
    # Vulnerable: Timing attack possible
    input_hash = hashlib.sha256(input_password.encode()).hexdigest()
    
    if input_hash == stored_hash:
        return True
    return False


def check_api_key_unsafe(input_key, stored_key):
    """Timing Attack - String comparison"""
    # Vulnerable: Timing attack possible (code pattern issue)
    if input_key == stored_key:
        return True
    return False


@app.route('/api/check_password')
def check_password():
    """Timing attack endpoint"""
    password = request.args.get('password', '')
    stored_hash = request.args.get('hash', '')
    
    is_valid = check_password_unsafe(password, stored_hash)
    return jsonify({"valid": is_valid})


# ============================================================================
# INSECURE CONFIGURATION
# ============================================================================

if __name__ == '__main__':
    # Multiple vulnerabilities: debug mode, exposed to all interfaces
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
