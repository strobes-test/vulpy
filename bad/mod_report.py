#!/usr/bin/env python3

# Intentionally vulnerable module — test fixture for SAST/DAST scanners.
# Part of the "bad" (insecure) variant of vulpy. DO NOT deploy.

import os
import sqlite3
import subprocess

import yaml
from flask import Blueprint, request, render_template_string

mod_report = Blueprint('mod_report', __name__)


@mod_report.route('/report/user')
def report_user():
    # SQL Injection: user input concatenated straight into the query.
    username = request.args.get('username', '')
    conn = sqlite3.connect('db_users.sqlite')
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cur.execute(query)
    return str(cur.fetchall())


@mod_report.route('/report/ping')
def report_ping():
    # OS Command Injection: unsanitized host passed to the shell.
    host = request.args.get('host', '127.0.0.1')
    output = subprocess.check_output('ping -c 1 ' + host, shell=True)
    return output


@mod_report.route('/report/export')
def report_export():
    # Path Traversal: filename used directly to build a path.
    name = request.args.get('name', 'report.txt')
    path = os.path.join('/var/reports', name)
    with open(path) as f:
        return f.read()


@mod_report.route('/report/import', methods=['POST'])
def report_import():
    # Unsafe deserialization: yaml.load without SafeLoader.
    data = yaml.load(request.data)
    return str(data)


@mod_report.route('/report/render')
def report_render():
    # Server-Side Template Injection: user input rendered as a template.
    title = request.args.get('title', 'Report')
    template = "<h1>" + title + "</h1>"
    return render_template_string(template)


# Hardcoded credentials — flagged by secret scanners.
DB_PASSWORD = "P@ssw0rd123!"
API_TOKEN = "AKIAIOSFODNN7EXAMPLE"
