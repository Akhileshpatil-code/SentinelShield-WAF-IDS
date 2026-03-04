from flask import Flask, request, jsonify

app = Flask(__name__)

@app.get("/")
def home():
    return "Victim App OK"

@app.get("/search")
def search():
    q = request.args.get("q", "")
    return jsonify({"endpoint": "search", "q": q})

@app.get("/login")
def login():
    user = request.args.get("username", "")
    pw = request.args.get("password", "")
    return jsonify({"endpoint": "login", "username": user, "password": pw})

@app.get("/file")
def file_read():
    name = request.args.get("name", "")
    return jsonify({"endpoint": "file", "name": name})

@app.get("/ping")
def ping():
    ip = request.args.get("ip", "")
    return jsonify({"endpoint": "ping", "ip": ip})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
