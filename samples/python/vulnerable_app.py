"""
INTENTIONALLY VULNERABLE Python/Flask application.
FOR TESTING PURPOSES ONLY — DO NOT DEPLOY.

Demonstrates OWASP Top 10 (2025) vulnerabilities for VulnScanner AI testing.
"""

import os
import hashlib
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

# A02: Hardcoded secret key
SECRET_KEY = "supersecretkey123"
DB_PASSWORD = "admin123"

# A05: Debug mode enabled
app.run(debug=True)


# ── A03: SQL Injection ────────────────────────────────────────────────────────
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: string concatenation in SQL query
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return str(cursor.fetchall())


# ── A03: XSS ─────────────────────────────────────────────────────────────────
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # VULNERABLE: user input rendered directly in template
    return render_template_string("<h1>Hello " + name + "</h1>")


# ── A03: Command Injection ────────────────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # VULNERABLE: shell=True with user input
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()


# ── A02: Weak hashing ─────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


# ── A10: SSRF ─────────────────────────────────────────────────────────────────
@app.route("/fetch")
def fetch_url():
    import requests
    target = request.args.get("url")
    # VULNERABLE: user-controlled URL passed directly to requests
    resp = requests.get(target)
    return resp.text


# ── A01: Path Traversal ───────────────────────────────────────────────────────
@app.route("/file")
def read_file():
    filename = request.args.get("name")
    # VULNERABLE: no path sanitisation
    with open(f"/var/uploads/{filename}") as f:
        return f.read()


# ── A02: Insecure TLS ─────────────────────────────────────────────────────────
def call_api(url: str):
    import requests
    # VULNERABLE: certificate verification disabled
    return requests.get(url, verify=False)


# ── A07: Weak JWT ─────────────────────────────────────────────────────────────
def decode_token(token: str):
    import jwt
    # VULNERABLE: signature verification disabled
    return jwt.decode(token, options={"verify_signature": False})


# ── A09: Logging sensitive data ───────────────────────────────────────────────
import logging
def login(username: str, password: str):
    # VULNERABLE: password logged in plaintext
    logging.info(f"Login attempt: username={username} password={password}")
    return username == "admin" and password == "secret"
