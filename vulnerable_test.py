"""
Vulnerable Python code for CodeQL scanning test
This file contains intentional security vulnerabilities for testing purposes
"""

import os
import sqlite3
import hashlib
from flask import Flask, request

app = Flask(__name__)

# Hardcoded credentials vulnerability
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"
DATABASE_PASSWORD = "SuperSecret123!"


@app.route('/search')
def search_user():
    """SQL Injection vulnerability"""
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Direct string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return str(results)


@app.route('/execute')
def execute_command():
    """Command Injection vulnerability"""
    filename = request.args.get('filename')
    
    # Vulnerable: Unsanitized user input in OS command
    os.system('cat ' + filename)
    
    return "Command executed"


@app.route('/read_file')
def read_file():
    """Path Traversal vulnerability"""
    filepath = request.args.get('file')
    
    # Vulnerable: No path validation
    with open('/var/www/files/' + filepath, 'r') as f:
        content = f.read()
    
    return content


@app.route('/eval_code')
def eval_code():
    """Code Injection vulnerability"""
    user_code = request.args.get('code')
    
    # Extremely dangerous: executing arbitrary code
    result = eval(user_code)
    
    return str(result)


def weak_hash(password):
    """Weak cryptographic hash (MD5)"""
    # Vulnerable: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def insecure_random():
    """Insecure randomness"""
    import random
    
    # Vulnerable: random module is not cryptographically secure
    token = random.randint(100000, 999999)
    return token


@app.route('/download')
def download_file():
    """Server-Side Request Forgery (SSRF)"""
    url = request.args.get('url')
    
    import urllib.request
    # Vulnerable: Fetching arbitrary URLs without validation
    response = urllib.request.urlopen(url)
    
    return response.read()


if __name__ == '__main__':
    # Vulnerable: Debug mode enabled and binding to all interfaces
    app.run(debug=True, host='0.0.0.0')

