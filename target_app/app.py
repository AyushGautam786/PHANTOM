"""
PHANTOM demo target — intentionally vulnerable Flask app.
Contains: SSTI, hardcoded secret, debug mode, SQL injection pattern.
USE ONLY FOR DEMO. Never deploy this.
"""

from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "hardcoded_secret_12345"  # Bandit will flag this
app.debug = True                            # Bandit will flag this

# Intentional SSTI vulnerability
@app.route("/render")
def render_page():
    template = request.args.get("template", "Hello World")
    return render_template_string(template)  # SSTI: user input as template

# Intentional SQL injection pattern
@app.route("/user")
def get_user():
    uid = request.args.get("id", "1")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {uid}"  # SQLi
    try:
        cursor.execute(query)
    except Exception:
        pass
    return "User endpoint"

@app.route("/")
def index():
    return "<h1>Demo App</h1><p>Target for PHANTOM assessment.</p>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
