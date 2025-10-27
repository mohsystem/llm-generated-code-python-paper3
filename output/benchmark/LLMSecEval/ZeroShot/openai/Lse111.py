import platform
import re
import subprocess
from flask import Flask, request, Response

app = Flask(__name__)

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")
_IPV4_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$")
_ALLOWED_CHARS = re.compile(r"^[A-Za-z0-9.:-]+$")

def _is_valid_host(host: str) -> bool:
    if host is None:
        return False
    host = host.strip()
    if not host or len(host) > 253:
        return False
    if not _ALLOWED_CHARS.match(host):
        return False
    if _IPV4_RE.match(host):
        return True
    if ":" in host:
        # basic IPv6 sanity; avoid DNS resolution here
        hex_cols = host.split(":")
        if 2 <= len(hex_cols) <= 8 and all((c == "" or re.fullmatch(r"[0-9A-Fa-f]{0,4}", c)) for c in hex_cols):
            return True
        return False
    return bool(_HOSTNAME_RE.match(host))

def ping(url: str) -> str:
    host = (url or "").strip()
    if not _is_valid_host(host):
        return "Invalid host"
    is_win = platform.system().lower().startswith("win")
    if is_win:
        cmd = ["ping", "-n", "2", "-w", "2000", host]
    else:
        cmd = ["ping", "-c", "2", "-W", "2", host]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        out = (cp.stdout or "") + (("\n" + cp.stderr) if cp.stderr else "")
        if len(out) > 100000:
            out = out[:100000] + "\n[truncated]"
        return out
    except subprocess.TimeoutExpired:
        return "[Timed out]"
    except Exception as e:
        return f"Error executing ping: {e}"

@app.get("/ping")
def ping_route():
    url = request.args.get("url", "").strip()
    if not _is_valid_host(url):
        return Response("Invalid host", status=400, mimetype="text/plain")
    return Response(ping(url), mimetype="text/plain")

if __name__ == "__main__":
    tests = ["localhost", "127.0.0.1", "::1", "example.com", "invalid_host!"]
    for t in tests:
        print(f"== ping({t}) ==")
        print(ping(t))
    # To run the web app instead, uncomment below line:
    # app.run(host="127.0.0.1", port=8081, debug=False)