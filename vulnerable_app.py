"""
Additional vulnerable Python code for CodeQL scanning
Contains more security vulnerabilities for comprehensive testing
"""

import pickle
import xml.etree.ElementTree as ET
import subprocess
import yaml
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

# Hard-coded secret key vulnerability
app.secret_key = "my-secret-key-12345"
JWT_SECRET = "jwt-super-secret-token"


@app.route('/render')
def render_template():
    """Server-Side Template Injection (SSTI)"""
    template = request.args.get('template', 'Hello World')
    
    # Vulnerable: User input directly in template
    return render_template_string(template)


@app.route('/deserialize')
def deserialize_data():
    """Insecure Deserialization with pickle"""
    import base64
    
    data = request.args.get('data')
    
    # Extremely vulnerable: pickle can execute arbitrary code
    decoded = base64.b64decode(data)
    obj = pickle.loads(decoded)
    
    return str(obj)


@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    """XML External Entity (XXE) vulnerability"""
    xml_data = request.data
    
    # Vulnerable: No protection against XXE attacks
    parser = ET.XMLParser()
    tree = ET.fromstring(xml_data, parser=parser)
    
    return ET.tostring(tree)


@app.route('/redirect')
def open_redirect():
    """Open Redirect vulnerability"""
    target = request.args.get('url')
    
    # Vulnerable: Redirecting to unvalidated URL
    return redirect(target)


@app.route('/run')
def run_command():
    """Command Injection with subprocess"""
    cmd = request.args.get('cmd')
    
    # Vulnerable: shell=True with user input
    result = subprocess.run(cmd, shell=True, capture_output=True)
    
    return result.stdout


@app.route('/yaml_load', methods=['POST'])
def load_yaml():
    """Insecure YAML deserialization"""
    yaml_data = request.data
    
    # Vulnerable: yaml.load without safe_load
    data = yaml.load(yaml_data, Loader=yaml.Loader)
    
    return str(data)


def ldap_query(username):
    """LDAP Injection vulnerability"""
    import ldap
    
    # Vulnerable: Unsanitized input in LDAP query
    ldap_conn = ldap.initialize('ldap://localhost')
    search_filter = f"(uid={username})"
    
    results = ldap_conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, search_filter)
    return results


@app.route('/upload', methods=['POST'])
def upload_file():
    """Unrestricted File Upload"""
    file = request.files['file']
    
    # Vulnerable: No file type validation, arbitrary file execution possible
    file.save('/var/www/uploads/' + file.filename)
    
    return 'File uploaded successfully'


@app.route('/log')
def log_data():
    """Log Injection vulnerability"""
    import logging
    
    user_input = request.args.get('data')
    
    # Vulnerable: Unsanitized user input in logs
    logging.info(f"User data: {user_input}")
    
    return "Logged"


def xpath_query(username):
    """XPath Injection vulnerability"""
    from lxml import etree
    
    xml = etree.parse('users.xml')
    
    # Vulnerable: Unsanitized input in XPath
    query = f"//user[username='{username}']"
    result = xml.xpath(query)
    
    return result


@app.route('/cookie')
def set_cookie():
    """Insecure Cookie (missing secure flags)"""
    from flask import make_response
    
    resp = make_response("Cookie set")
    
    # Vulnerable: Cookie without httponly and secure flags
    resp.set_cookie('session_id', '123456789', httponly=False, secure=False)
    
    return resp


def connect_database():
    """Cleartext transmission of sensitive information"""
    import mysql.connector
    
    # Vulnerable: Connection without SSL/TLS
    connection = mysql.connector.connect(
        host='database.example.com',
        user='admin',
        password='P@ssw0rd123',  # Also hardcoded password
        database='production',
        use_pure=True
    )
    
    return connection


if __name__ == '__main__':
    # Multiple vulnerabilities: debug mode, exposed to all interfaces, default port
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)

