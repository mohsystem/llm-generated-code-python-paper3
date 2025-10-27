import platform
import re
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

def is_valid_host(url: str) -> bool:
    if not isinstance(url, str):
        return False
    u = url.strip()
    if u.lower() == "localhost":
        return True
    if _IPV4_RE.match(u):
        return True
    return _HOST_RE.match(u) is not None

def secure_ping(url: str) -> str | None:
    if not is_valid_host(url):
        return None
    is_windows = platform.system().lower().startswith("win")
    cmd = ["ping", "-n", "1", "-w", "2000", url] if is_windows else ["ping", "-c", "1", "-W", "2", url]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=False)
        return url
    except Exception:
        return None

@app.get("/ping")
def ping():
    url = request.args.get("url", "")
    res = secure_ping(url)
    if res is None:
        return jsonify({"error": "invalid or ping failed"}), 400
    return jsonify({"url": res})

if __name__ == "__main__":
    tests = ["example.com", "127.0.0.1", "8.8.8.8", "invalid;;host", "localhost"]
    for t in tests:
        print(f"Input: {t} -> Returned: {secure_ping(t)}")
    # To run the web server, uncomment the next line:
    # app.run(host="127.0.0.1", port=5000, debug=False)