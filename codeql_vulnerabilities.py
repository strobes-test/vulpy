"""
CodeQL Code Scanning Vulnerabilities
This file contains intentional security vulnerabilities for CodeQL scanning tests
Covers various vulnerability types that CodeQL can detect
"""

import os
import sys
import json
import re
import hmac
import base64
import tempfile
import shutil
from flask import Flask, request, session, jsonify, make_response
from werkzeug.security import generate_password_hash
import jwt
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# ============================================================================
# HARDCODED SECRETS AND CREDENTIALS
# ============================================================================

# Hardcoded API keys
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_API_KEY = "sk_live_51HqwBCJm8cEXAMPLE"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# Hardcoded passwords
ADMIN_PASSWORD = "admin123"
DB_PASSWORD = "SuperSecretDBPassword123!"
ENCRYPTION_KEY = "my-encryption-key-12345"

# Hardcoded JWT secret
JWT_SECRET_KEY = "my-super-secret-jwt-key-do-not-share"


# ============================================================================
# SQL INJECTION VULNERABILITIES
# ============================================================================

@app.route('/user_search')
def user_search():
    """SQL Injection - String concatenation"""
    import sqlite3
    
    username = request.args.get('username', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


@app.route('/user_filter')
def user_filter():
    """SQL Injection - Format string"""
    import sqlite3
    
    user_id = request.args.get('id', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Format string injection
    query = "SELECT * FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


@app.route('/user_lookup')
def user_lookup():
    """SQL Injection - f-string"""
    import sqlite3
    
    email = request.args.get('email', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: f-string with user input
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


# ============================================================================
# COMMAND INJECTION VULNERABILITIES
# ============================================================================

@app.route('/ping_host')
def ping_host():
    """Command Injection - os.system"""
    host = request.args.get('host', '')
    
    # Vulnerable: User input in os.system
    os.system(f"ping -c 4 {host}")
    
    return "Ping executed"


@app.route('/list_files')
def list_files():
    """Command Injection - subprocess with shell=True"""
    import subprocess
    
    directory = request.args.get('dir', '.')
    
    # Vulnerable: shell=True with user input
    result = subprocess.run(f"ls -la {directory}", shell=True, capture_output=True)
    
    return result.stdout.decode()


@app.route('/grep_file')
def grep_file():
    """Command Injection - subprocess.Popen"""
    import subprocess
    
    pattern = request.args.get('pattern', '')
    filename = request.args.get('file', 'data.txt')
    
    # Vulnerable: User input in command
    process = subprocess.Popen(['grep', pattern, filename], stdout=subprocess.PIPE)
    output = process.communicate()[0]
    
    return output.decode()


@app.route('/execute_script')
def execute_script():
    """Command Injection - eval with os.system"""
    script = request.args.get('script', '')
    
    # Vulnerable: eval can execute arbitrary code
    eval(f"os.system('{script}')")
    
    return "Script executed"


# ============================================================================
# PATH TRAVERSAL VULNERABILITIES
# ============================================================================

@app.route('/read_config')
def read_config():
    """Path Traversal - Direct file access"""
    filename = request.args.get('file', 'config.json')
    
    # Vulnerable: No path validation
    with open(f'/etc/config/{filename}', 'r') as f:
        content = f.read()
    
    return content


@app.route('/download_file')
def download_file():
    """Path Traversal - os.path.join without validation"""
    filepath = request.args.get('path', '')
    
    # Vulnerable: User input in file path
    full_path = os.path.join('/var/www/files', filepath)
    
    with open(full_path, 'rb') as f:
        content = f.read()
    
    return content


@app.route('/delete_file')
def delete_file():
    """Path Traversal - shutil operations"""
    filename = request.args.get('file', '')
    
    # Vulnerable: No validation before deletion
    filepath = f'/tmp/uploads/{filename}'
    os.remove(filepath)
    
    return "File deleted"


# ============================================================================
# CODE INJECTION VULNERABILITIES
# ============================================================================

@app.route('/eval_input')
def eval_input():
    """Code Injection - eval()"""
    user_code = request.args.get('code', '')
    
    # Extremely vulnerable: executing arbitrary code
    result = eval(user_code)
    
    return str(result)


@app.route('/exec_input')
def exec_input():
    """Code Injection - exec()"""
    user_code = request.args.get('code', '')
    
    # Extremely vulnerable: executing arbitrary code
    exec(user_code)
    
    return "Code executed"


@app.route('/compile_code')
def compile_code():
    """Code Injection - compile() and eval()"""
    user_code = request.args.get('code', '')
    
    # Vulnerable: Compiling and executing user code
    compiled = compile(user_code, '<string>', 'exec')
    eval(compiled)
    
    return "Code compiled and executed"


# ============================================================================
# INSECURE DESERIALIZATION
# ============================================================================

@app.route('/unpickle_data')
def unpickle_data():
    """Insecure Deserialization - pickle"""
    import pickle
    
    data = request.args.get('data', '')
    
    # Vulnerable: pickle can execute arbitrary code
    decoded = base64.b64decode(data)
    obj = pickle.loads(decoded)
    
    return str(obj)


@app.route('/load_yaml')
def load_yaml():
    """Insecure Deserialization - yaml.load"""
    import yaml
    
    yaml_data = request.data
    
    # Vulnerable: yaml.load without safe_load
    data = yaml.load(yaml_data, Loader=yaml.Loader)
    
    return jsonify(data)


@app.route('/marshal_load')
def marshal_load():
    """Insecure Deserialization - marshal"""
    import marshal
    
    data = request.args.get('data', '')
    
    # Vulnerable: marshal can deserialize arbitrary objects
    decoded = base64.b64decode(data)
    obj = marshal.loads(decoded)
    
    return str(obj)


# ============================================================================
# WEAK CRYPTOGRAPHY
# ============================================================================

def hash_password_md5(password):
    """Weak Hash - MD5"""
    import hashlib
    
    # Vulnerable: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password):
    """Weak Hash - SHA1"""
    import hashlib
    
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


def encrypt_data_weak(data):
    """Weak Encryption - ECB mode"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    
    # Vulnerable: ECB mode is insecure
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY.encode()[:16]), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padded_data = data.encode().ljust(16, b' ')
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(ciphertext).decode()


# ============================================================================
# SSRF (Server-Side Request Forgery)
# ============================================================================

@app.route('/fetch_url')
def fetch_url():
    """SSRF - urllib"""
    import urllib.request
    
    url = request.args.get('url', '')
    
    # Vulnerable: Fetching arbitrary URLs
    response = urllib.request.urlopen(url)
    return response.read()


@app.route('/proxy_request')
def proxy_request():
    """SSRF - requests library"""
    url = request.args.get('url', '')
    
    # Vulnerable: No URL validation
    response = requests.get(url)
    return response.text


@app.route('/fetch_internal')
def fetch_internal():
    """SSRF - Internal network access"""
    path = request.args.get('path', '')
    
    # Vulnerable: Accessing internal resources
    url = f"http://localhost:8080/api/{path}"
    response = requests.get(url)
    return response.json()


# ============================================================================
# XSS (Cross-Site Scripting)
# ============================================================================

@app.route('/render_template')
def render_template():
    """XSS - Template injection"""
    from flask import render_template_string
    
    template = request.args.get('template', 'Hello')
    
    # Vulnerable: User input in template
    return render_template_string(template)


@app.route('/display_comment')
def display_comment():
    """XSS - Unsanitized output"""
    comment = request.args.get('comment', '')
    
    # Vulnerable: No HTML escaping
    html = f"<div>{comment}</div>"
    return html


@app.route('/set_cookie_unsafe')
def set_cookie_unsafe():
    """XSS - Cookie manipulation"""
    value = request.args.get('value', '')
    
    # Vulnerable: User input in cookie without sanitization
    resp = make_response("Cookie set")
    resp.set_cookie('user_data', value, httponly=False, secure=False)
    
    return resp


# ============================================================================
# XXE (XML External Entity)
# ============================================================================

@app.route('/parse_xml')
def parse_xml():
    """XXE - XML parsing without protection"""
    import xml.etree.ElementTree as ET
    
    xml_data = request.data
    
    # Vulnerable: No XXE protection
    parser = ET.XMLParser()
    tree = ET.fromstring(xml_data, parser=parser)
    
    return ET.tostring(tree)


@app.route('/parse_xml_lxml')
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
    import ldap
    
    # Vulnerable: Unsanitized input in LDAP query
    ldap_conn = ldap.initialize('ldap://localhost')
    search_filter = f"(uid={username})"
    
    results = ldap_conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, search_filter)
    return results


# ============================================================================
# XPATH INJECTION
# ============================================================================

def xpath_search(username):
    """XPath Injection"""
    from lxml import etree
    
    xml = etree.parse('users.xml')
    
    # Vulnerable: Unsanitized input in XPath
    query = f"//user[username='{username}']"
    result = xml.xpath(query)
    
    return result


# ============================================================================
# INSECURE COOKIES
# ============================================================================

@app.route('/set_session')
def set_session():
    """Insecure Cookie - Missing flags"""
    session_id = request.args.get('session_id', '12345')
    
    # Vulnerable: Cookie without secure and httponly flags
    resp = make_response("Session set")
    resp.set_cookie('session', session_id, httponly=False, secure=False, samesite=None)
    
    return resp


# ============================================================================
# INFORMATION DISCLOSURE
# ============================================================================

@app.route('/error_handler')
def error_handler():
    """Information Disclosure - Stack traces"""
    try:
        # Vulnerable: Exposing stack traces
        result = 1 / 0
    except Exception as e:
        import traceback
        # Vulnerable: Returning full traceback
        return str(traceback.format_exc())


@app.route('/debug_info')
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


# ============================================================================
# INSECURE FILE OPERATIONS
# ============================================================================

@app.route('/upload_file')
def upload_file():
    """Unrestricted File Upload"""
    file = request.files['file']
    
    # Vulnerable: No file type validation
    file.save(f'/var/www/uploads/{file.filename}')
    
    return 'File uploaded'


@app.route('/create_temp_file')
def create_temp_file():
    """Insecure Temporary File"""
    filename = request.args.get('filename', 'temp.txt')
    
    # Vulnerable: Predictable temporary file name
    temp_path = f'/tmp/{filename}'
    
    with open(temp_path, 'w') as f:
        f.write('temporary data')
    
    return f"File created at {temp_path}"


# ============================================================================
# LOG INJECTION
# ============================================================================

@app.route('/log_user_action')
def log_user_action():
    """Log Injection"""
    import logging
    
    action = request.args.get('action', '')
    user_id = request.args.get('user_id', '')
    
    # Vulnerable: Unsanitized user input in logs
    logging.info(f"User {user_id} performed action: {action}")
    
    return "Action logged"


# ============================================================================
# OPEN REDIRECT
# ============================================================================

@app.route('/redirect')
def open_redirect():
    """Open Redirect"""
    from flask import redirect
    
    target = request.args.get('url', '/')
    
    # Vulnerable: Redirecting to unvalidated URL
    return redirect(target)


# ============================================================================
# INSECURE JWT
# ============================================================================

def create_jwt_weak(payload):
    """Insecure JWT - Hardcoded secret"""
    # Vulnerable: Using hardcoded secret
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
    return token


def verify_jwt_weak(token):
    """Insecure JWT - No algorithm specification"""
    # Vulnerable: Algorithm not specified (algorithm confusion attack)
    payload = jwt.decode(token, JWT_SECRET_KEY)
    return payload


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


# ============================================================================
# INSECURE COMPARISON
# ============================================================================

def check_password_unsafe(input_password, stored_hash):
    """Timing Attack - Insecure comparison"""
    import hashlib
    
    # Vulnerable: Timing attack possible
    input_hash = hashlib.sha256(input_password.encode()).hexdigest()
    
    if input_hash == stored_hash:
        return True
    return False


def check_api_key_unsafe(input_key):
    """Timing Attack - String comparison"""
    # Vulnerable: Timing attack possible
    if input_key == AWS_ACCESS_KEY:
        return True
    return False


# ============================================================================
# INSECURE CONFIGURATION
# ============================================================================

if __name__ == '__main__':
    # Multiple vulnerabilities: debug mode, exposed to all interfaces
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
