"""
Unique Vulnerable Python Code for CodeQL Scanning
Contains different security vulnerabilities not found in other branches
"""

import json
import uuid
import tempfile
import shutil
import threading
from flask import Flask, request, jsonify, session, make_response, redirect
from pymongo import MongoClient
import jwt
import bcrypt
from werkzeug.utils import secure_filename
import os
import secrets
import hmac
import hashlib

app = Flask(__name__)

# Hardcoded secrets
MONGODB_PASSWORD = "mongodb-password-123"
JWT_ALGORITHM = "HS256"
SESSION_SECRET = "session-secret-key-456"


@app.route('/api/nosql_injection')
def nosql_injection():
    """NoSQL Injection vulnerability in MongoDB"""
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    
    client = MongoClient(f"mongodb://admin:{MONGODB_PASSWORD}@localhost:27017/")
    db = client['app_db']
    users = db['users']
    
    # CRITICAL: NoSQL injection - user input directly in query
    query = {"username": username, "password": password}
    user = users.find_one(query)
    
    if user:
        return jsonify({"authenticated": True, "user": str(user)})
    return jsonify({"authenticated": False})


@app.route('/api/graphql', methods=['POST'])
def graphql_injection():
    """GraphQL Injection vulnerability"""
    query = request.json.get('query', '')
    
    # CRITICAL: Direct execution of GraphQL query without validation
    # This simulates a vulnerable GraphQL endpoint
    if 'query' in query.lower():
        # Vulnerable: User-controlled GraphQL query execution
        result = eval(f"execute_graphql('{query}')")
        return jsonify({"data": result})
    
    return jsonify({"error": "Invalid query"})


@app.route('/api/jwt_weak')
def weak_jwt_implementation():
    """Weak JWT implementation vulnerabilities"""
    payload = request.json.get('payload', {})
    
    # CRITICAL: Using weak secret and no algorithm validation
    token = jwt.encode(payload, SESSION_SECRET, algorithm=JWT_ALGORITHM)
    
    # CRITICAL: Decoding without verifying signature
    decoded = jwt.decode(token, options={"verify_signature": False})
    
    return jsonify({"token": token, "decoded": decoded})


@app.route('/api/jwt_none')
def jwt_none_algorithm():
    """JWT None algorithm vulnerability"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    # CRITICAL: Accepting tokens with 'none' algorithm
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        if decoded.get('alg') == 'none':
            # Vulnerable: Accepting unsigned tokens
            return jsonify({"admin": decoded.get('admin', False)})
    except:
        pass
    
    return jsonify({"error": "Invalid token"})


@app.route('/api/password_reset')
def insecure_password_reset():
    """Insecure Password Reset Implementation"""
    email = request.json.get('email', '')
    token = request.json.get('token', '')
    new_password = request.json.get('new_password', '')
    
    # CRITICAL: Weak token generation (predictable)
    reset_token = str(uuid.uuid4()).replace('-', '')[:16]
    
    # CRITICAL: No token expiration check
    # CRITICAL: No rate limiting on password reset attempts
    if token == reset_token:
        # CRITICAL: Weak password policy enforcement
        if len(new_password) >= 4:  # Too weak!
            return jsonify({"reset": True})
    
    return jsonify({"reset": False})


@app.route('/api/race_condition_transfer')
def race_condition_money_transfer():
    """Race Condition in Financial Transaction"""
    amount = float(request.json.get('amount', 0))
    from_account = request.json.get('from', '')
    to_account = request.json.get('to', '')
    
    # CRITICAL: Race condition - no locking mechanism
    balance = get_account_balance(from_account)
    
    if balance >= amount:
        # Race condition window: balance could change here
        deduct_balance(from_account, amount)
        add_balance(to_account, amount)
        return jsonify({"transferred": amount})
    
    return jsonify({"error": "Insufficient funds"})


@app.route('/api/idor_file')
def insecure_direct_object_reference_file():
    """IDOR - Insecure Direct Object Reference for Files"""
    file_id = request.args.get('file_id', '')
    user_id = session.get('user_id', 'user123')
    
    # CRITICAL: No authorization check - users can access any file
    file_path = f"/user_files/{file_id}.pdf"
    
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            return f.read()
    
    return jsonify({"error": "File not found"})


@app.route('/api/business_logic_flaw')
def business_logic_vulnerability():
    """Business Logic Flaw - Price Manipulation"""
    product_id = request.json.get('product_id', '')
    quantity = int(request.json.get('quantity', 1))
    price = float(request.json.get('price', 0))
    
    # CRITICAL: Client-controlled price - should be server-side
    total = price * quantity
    
    # CRITICAL: No validation that price matches server price
    if process_payment(total):
        return jsonify({"purchased": True, "total": total})
    
    return jsonify({"error": "Payment failed"})


@app.route('/api/rate_limit_bypass')
def rate_limit_bypass():
    """Rate Limiting Bypass Vulnerability"""
    api_key = request.headers.get('X-API-Key', '')
    
    # CRITICAL: Rate limiting based on easily spoofed header
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    # CRITICAL: No proper rate limiting implementation
    if check_rate_limit(client_ip):
        return jsonify({"limited": True})
    
    return jsonify({"allowed": True})


@app.route('/api/host_header_injection')
def host_header_injection():
    """Host Header Injection vulnerability"""
    host = request.headers.get('Host', '')
    
    # CRITICAL: Using Host header without validation
    redirect_url = f"https://{host}/callback"
    
    return redirect(redirect_url)


@app.route('/api/parameter_pollution')
def http_parameter_pollution():
    """HTTP Parameter Pollution vulnerability"""
    user_id = request.args.get('user_id', '')
    action = request.args.get('action', '')
    
    # CRITICAL: Parameter pollution - multiple values not handled correctly
    # If user_id=admin&user_id=user123, which one is used?
    if user_id == 'admin' and action == 'delete':
        delete_all_users()
        return jsonify({"deleted": True})
    
    return jsonify({"error": "Unauthorized"})


@app.route('/api/insecure_temp_file')
def insecure_temporary_file():
    """Insecure Temporary File Creation"""
    content = request.json.get('content', '')
    
    # CRITICAL: Predictable temporary file name
    temp_file = f"/tmp/user_data_{session.get('user_id', '123')}.txt"
    
    # CRITICAL: World-readable temporary file
    with open(temp_file, 'w') as f:
        f.write(content)
    
    # CRITICAL: File permissions not set securely
    os.chmod(temp_file, 0o666)  # World-readable and writable
    
    return jsonify({"file": temp_file})


@app.route('/api/insecure_uuid')
def insecure_uuid_generation():
    """Insecure UUID Generation for Security Tokens"""
    # CRITICAL: Using uuid1() which includes MAC address (predictable)
    token = str(uuid.uuid1())
    
    # CRITICAL: Using uuid4() but with predictable seed
    import random
    random.seed(12345)
    session_id = str(uuid.uuid4())
    
    return jsonify({"token": token, "session_id": session_id})


@app.route('/api/weak_password_policy')
def weak_password_policy():
    """Weak Password Policy Enforcement"""
    password = request.json.get('password', '')
    
    # CRITICAL: Extremely weak password requirements
    if len(password) >= 3:  # Should be at least 12+ with complexity
        return jsonify({"valid": True})
    
    return jsonify({"valid": False, "error": "Password too short"})


@app.route('/api/insecure_reflection')
def insecure_reflection():
    """Insecure Reflection - Dynamic Code Loading"""
    module_name = request.args.get('module', '')
    function_name = request.args.get('function', '')
    
    # CRITICAL: Loading and executing arbitrary modules/functions
    module = __import__(module_name)
    func = getattr(module, function_name)
    
    result = func()
    return jsonify({"result": str(result)})


@app.route('/api/insecure_env')
def insecure_environment_variables():
    """Insecure Environment Variable Usage"""
    import os
    
    # CRITICAL: Exposing environment variables in API response
    return jsonify({
        "database_url": os.environ.get('DATABASE_URL'),
        "api_key": os.environ.get('API_KEY'),
        "secret": os.environ.get('SECRET_KEY'),
        "all_env": dict(os.environ)
    })


@app.route('/api/insecure_config_file')
def insecure_configuration_file():
    """Insecure Configuration File Reading"""
    config_path = request.args.get('config', 'config.json')
    
    # CRITICAL: Reading arbitrary configuration files
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # CRITICAL: Exposing sensitive configuration
    return jsonify(config)


@app.route('/api/insecure_caching')
def insecure_caching():
    """Insecure Caching Implementation"""
    user_id = request.args.get('user_id', '')
    sensitive_data = get_user_sensitive_data(user_id)
    
    # CRITICAL: Caching sensitive data without proper invalidation
    cache_key = f"user_{user_id}"
    cache[cache_key] = sensitive_data
    
    # CRITICAL: Cache poisoning - no validation of cached data
    return jsonify(cache.get(cache_key))


@app.route('/api/insecure_serialization')
def insecure_serialization():
    """Insecure Serialization (different from pickle)"""
    import marshal
    
    data = request.json.get('data', '')
    
    # CRITICAL: Using marshal for serialization (can execute code)
    serialized = marshal.dumps(compile(data, '<string>', 'exec'))
    
    # CRITICAL: Deserializing without validation
    code_obj = marshal.loads(serialized)
    exec(code_obj)
    
    return jsonify({"serialized": True})


@app.route('/api/insecure_dependency')
def insecure_dependency_loading():
    """Insecure Dynamic Dependency Loading"""
    package_name = request.args.get('package', '')
    
    # CRITICAL: Loading arbitrary packages at runtime
    import importlib
    try:
        module = importlib.import_module(package_name)
        return jsonify({"loaded": True, "module": str(module)})
    except:
        return jsonify({"error": "Failed to load"})


@app.route('/api/type_confusion')
def type_confusion():
    """Type Confusion Vulnerability"""
    user_input = request.json.get('input', '')
    
    # CRITICAL: No type validation before operations
    if isinstance(user_input, str):
        # Vulnerable: Could be manipulated to different type
        result = user_input + " processed"
    else:
        # Type confusion: treating non-string as string
        result = str(user_input) + " processed"
    
    # CRITICAL: Unsafe type operations
    return jsonify({"result": result, "type": type(user_input).__name__})


@app.route('/api/memory_disclosure')
def memory_disclosure():
    """Memory Disclosure Vulnerability"""
    data = request.json.get('data', '')
    
    # CRITICAL: Reading beyond buffer boundaries
    buffer = bytearray(100)
    data_bytes = data.encode('utf-8')
    
    # CRITICAL: No bounds checking - potential memory disclosure
    for i in range(min(len(data_bytes), 200)):  # Reading beyond buffer
        if i < len(buffer):
            buffer[i] = data_bytes[i % len(data_bytes)]
    
    return jsonify({"buffer": buffer.hex()})


@app.route('/api/insecure_session_storage')
def insecure_session_storage():
    """Insecure Session Storage"""
    user_data = request.json.get('user_data', {})
    
    # CRITICAL: Storing sensitive data in client-side session
    session['credit_card'] = user_data.get('credit_card')
    session['ssn'] = user_data.get('ssn')
    session['password'] = user_data.get('password')
    
    # CRITICAL: Session data not encrypted
    return jsonify({"session_id": session.sid})


@app.route('/api/clickjacking')
def clickjacking_vulnerability():
    """Missing Clickjacking Protection"""
    response = make_response(jsonify({"content": "sensitive action"}))
    
    # CRITICAL: Missing X-Frame-Options header
    # CRITICAL: Missing Content-Security-Policy frame-ancestors
    
    return response


@app.route('/api/insecure_error_details')
def insecure_error_details():
    """Insecure Error Message Details"""
    operation = request.json.get('operation', '')
    
    try:
        if operation == 'database':
            # CRITICAL: Exposing database structure in errors
            raise Exception("Table 'users' doesn't exist. Available tables: admin_users, payment_info, credit_cards")
        elif operation == 'file':
            # CRITICAL: Exposing file system structure
            raise FileNotFoundError("/var/www/secret/config.ini not found")
        elif operation == 'auth':
            # CRITICAL: Exposing authentication mechanism details
            raise Exception("JWT token expired. Secret key: " + SESSION_SECRET)
    except Exception as e:
        return jsonify({
            "error": str(e),
            "type": type(e).__name__,
            "traceback": str(e.__traceback__)
        })
    
    return jsonify({"success": True})


@app.route('/api/insecure_file_permissions')
def insecure_file_permissions():
    """Insecure File Permissions"""
    filename = request.json.get('filename', 'data.txt')
    content = request.json.get('content', '')
    
    file_path = f"/app/data/{filename}"
    
    # CRITICAL: Creating files with insecure permissions
    with open(file_path, 'w') as f:
        f.write(content)
    
    # CRITICAL: World-writable files
    os.chmod(file_path, 0o777)
    
    return jsonify({"created": file_path})


# Helper functions (vulnerable implementations)
def get_account_balance(account):
    return 1000.0  # Mock function

def deduct_balance(account, amount):
    pass  # Mock function

def add_balance(account, amount):
    pass  # Mock function

def process_payment(amount):
    return True  # Mock function

def check_rate_limit(ip):
    return False  # Mock function

def delete_all_users():
    pass  # Mock function

def get_user_sensitive_data(user_id):
    return {"ssn": "123-45-6789", "credit_card": "4532-1234-5678-9010"}

cache = {}

def execute_graphql(query):
    return {"data": "executed"}  # Mock function

if __name__ == '__main__':
    # CRITICAL: Multiple security misconfigurations
    app.config['SECRET_KEY'] = SESSION_SECRET
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = False
    app.run(host='0.0.0.0', port=8080, debug=True, threaded=True)

