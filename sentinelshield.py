from flask import Flask, request, Response, jsonify
import time, json, os
import requests
from collections import defaultdict, deque
from rules import match_rules

APP = Flask(__name__)

UPSTREAM = "http://127.0.0.1:5001"          # victim app
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "sentinel.log")

# Rate limiting: max N requests per WINDOW seconds (per IP)
WINDOW = 20
MAX_REQ = 25

# Track timestamps per IP
ip_hits = defaultdict(lambda: deque())

# Basic counters for dashboard
stats = {
    "blocked": 0,
    "allowed": 0,
    "by_category": defaultdict(int),
    "top_ips": defaultdict(int),
    "events": deque(maxlen=200)
}

def get_client_ip():
    # In lab: use remote_addr
    return request.remote_addr or "unknown"

def log_event(event: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    stats["events"].appendleft(event)
    stats["top_ips"][event["ip"]] += 1
    if event["action"] == "BLOCK":
        stats["blocked"] += 1
        stats["by_category"][event.get("category", "Unknown")] += 1
    else:
        stats["allowed"] += 1

def is_rate_limited(ip: str):
    now = time.time()
    dq = ip_hits[ip]
    # remove old hits
    while dq and (now - dq[0]) > WINDOW:
        dq.popleft()
    if len(dq) >= MAX_REQ:
        return True, len(dq)
    dq.append(now)
    return False, len(dq)

def inspect_request():
    # Inspect URL, args, headers, body (GET/POST)
    parts = []
    parts.append(request.path or "")
    parts.append(request.query_string.decode(errors="ignore"))
    for k, v in request.headers.items():
        parts.append(f"{k}:{v}")
    try:
        body = request.get_data(as_text=True)
        parts.append(body)
    except Exception:
        pass
    text = " ".join(parts)
    hits = match_rules(text)
    return hits, text


from flask import render_template_string

@APP.get("/dashboard")
def dashboard():
    top_ips_sorted = sorted(stats["top_ips"].items(), key=lambda x: x[1], reverse=True)[:10]
    by_cat_sorted = sorted(stats["by_category"].items(), key=lambda x: x[1], reverse=True)

    html = """
    <html>
    <head>
        <title>SentinelShield Dashboard</title>
        <style>
            body { font-family: Arial; background:#111; color:#eee; }
            h1 { color:#00ff88; }
            table { border-collapse: collapse; width: 60%; }
            th, td { border:1px solid #444; padding:8px; }
            th { background:#222; }
        </style>
    </head>
    <body>
        <h1>SentinelShield Security Dashboard</h1>
        <p><b>Allowed Requests:</b> {{allowed}}</p>
        <p><b>Blocked Requests:</b> {{blocked}}</p>

        <h2>Attack Categories</h2>
        <table>
            <tr><th>Category</th><th>Count</th></tr>
            {% for cat, count in by_cat %}
            <tr><td>{{cat}}</td><td>{{count}}</td></tr>
            {% endfor %}
        </table>

        <h2>Top IP Addresses</h2>
        <table>
            <tr><th>IP</th><th>Requests</th></tr>
            {% for ip, count in top_ips %}
            <tr><td>{{ip}}</td><td>{{count}}</td></tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """
    return render_template_string(html,
                                  allowed=stats["allowed"],
                                  blocked=stats["blocked"],
                                  by_cat=by_cat_sorted,
                                  top_ips=top_ips_sorted)

    # Simple JSON dashboard for reporting
    top_ips_sorted = sorted(stats["top_ips"].items(), key=lambda x: x[1], reverse=True)[:10]
    by_cat_sorted = sorted(stats["by_category"].items(), key=lambda x: x[1], reverse=True)
    return jsonify({
        "allowed": stats["allowed"],
        "blocked": stats["blocked"],
        "top_ips": top_ips_sorted,
        "by_category": by_cat_sorted,
        "recent_events": list(stats["events"])[:20]
    })

@APP.route("/", defaults={"path": ""}, methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
@APP.route("/<path:path>", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
def proxy(path):
    ip = get_client_ip()

    limited, count = is_rate_limited(ip)
    if limited:
        event = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "method": request.method,
            "path": "/" + path,
            "category": "RateLimit",
            "action": "BLOCK",
            "reason": f"Exceeded {MAX_REQ} req/{WINDOW}s (seen={count})"
        }
        log_event(event)
        return Response("Blocked: rate limit\n", status=429)

    hits, _ = inspect_request()
    if hits:
        event = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "method": request.method,
            "path": "/" + path,
            "category": ",".join(hits),
            "action": "BLOCK",
            "reason": "Signature match"
        }
        log_event(event)
        return Response("Blocked: malicious pattern detected\n", status=403)

    # Forward to upstream (victim app)
    url = f"{UPSTREAM}/{path}"
    try:
        upstream_resp = requests.request(
            method=request.method,
            url=url,
            params=request.args,
            data=request.get_data(),
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            allow_redirects=False,
            timeout=5
        )
    except Exception as e:
        event = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "method": request.method,
            "path": "/" + path,
            "category": "UpstreamError",
            "action": "BLOCK",
            "reason": str(e)
        }
        log_event(event)
        return Response("Upstream error\n", status=502)

    event = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "method": request.method,
        "path": "/" + path,
        "category": "Normal",
        "action": "ALLOW",
        "reason": f"Forwarded ({upstream_resp.status_code})"
    }
    log_event(event)

    resp = Response(upstream_resp.content, status=upstream_resp.status_code)
    for k, v in upstream_resp.headers.items():
        if k.lower() not in ["content-encoding", "transfer-encoding", "connection"]:
            resp.headers[k] = v
    return resp

if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=5000, debug=False)
