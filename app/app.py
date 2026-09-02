import os
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# Load the secret from the environment. Never define credentials as
# static strings in source -- anything committed here is compromised
# the moment it is pushed, and stays in history after it is deleted.
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

if not AWS_SECRET_KEY:
    raise ValueError("AWS_SECRET_ACCESS_KEY environment variable is not set")

# Clean healthcheck endpoint
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200

@app.route("/user", methods=["GET"])
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # RULE: semgrep python.lang.security.sqli.sqli-fstring
    # SQL injection via direct f-string interpolation into raw SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return jsonify({"query_executed": query})

@app.route("/ping", methods=["GET"])
def ping():
    target = request.args.get("target", "127.0.0.1")
    # RULE: semgrep python.lang.security.insecure-use-subprocess-fn
    # Command injection via untrusted user input passed into subprocess with shell=True
    result = subprocess.run(f"ping -c 1 {target}", shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout})

if __name__ == "__main__":
    # RULE: semgrep python.flask.security.audit.app-run-param-config
    # Insecure binding to 0.0.0.0 with debug mode enabled
    app.run(host="0.0.0.0", port=5000, debug=True)