from __future__ import annotations
import os
import platform
import re
import subprocess
import sys
from typing import Tuple
from urllib.parse import urlparse

try:
    from flask import Flask, request, Response
    FLASK_AVAILABLE = True
except Exception:
    FLASK_AVAILABLE = False
    # Fallback dummy app to allow running tests even if Flask isn't installed
    class Dummy:
        def route(self, *_args, **_kwargs):
            def deco(fn):
                return fn
            return deco
        def get(self, *args, **kwargs):
            return self.route(*args, **kwargs)
        def run(self, *args, **kwargs):
            print("Flask not available; HTTP server not started.")
    Flask = lambda name: Dummy()  # type: ignore
    Response = lambda *args, **kwargs: None  # type: ignore
    request = type("Req", (), {"args": {}})  # type: ignore

app = Flask(__name__)

IPV4 = re.compile(r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$")
HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$")

def _extract_host(input_url: str) -> str:
    if not input_url:
        return ""
    s = input_url.strip()
    if not s:
        return ""
    try:
        parsed = urlparse(s)
        if parsed.hostname:
            return parsed.hostname
    except Exception:
        pass
    # Try manual stripping of scheme and path
    if "://" in s:
        s = s.split("://", 1)[1]
    for sep in ["/", "?", "#"]:
        if sep in s:
            s = s.split(sep, 1)[0]
    return s.strip()

def _is_valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if not all(c.isalnum() or c in ".-" for c in host):
        return False
    if host.lower() == "localhost":
        return True
    if IPV4.match(host):
        return True
    return bool(HOSTNAME.match(host))

def ping_url(url: str) -> Tuple[bool, str]:
    host = _extract_host(url)
    if not _is_valid_host(host):
        return False, "Error: invalid or unsafe URL"
    is_windows = platform.system().lower().startswith("win")
    args = ["ping"]
    if is_windows:
        args += ["-n", "1", "-w", "2000", host]
    else:
        args += ["-c", "1", "-W", "2", host]
    try:
        subprocess.run(args, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    except subprocess.TimeoutExpired:
        return False, f"Error: ping timeout for URL: {host}"
    except Exception:
        return False, "Error: failed to run ping"
    return True, f"URL: {host}"

@app.get("/ping")
def ping():
    url = request.args.get("url", "") if hasattr(request, "args") else ""
    ok, msg = ping_url(url)
    status = 200 if ok else 400
    if FLASK_AVAILABLE:
        return Response(msg, status=status, mimetype="text/plain; charset=utf-8")
    return msg  # dummy fallback

if __name__ == "__main__":
    # Five test cases
    tests = [
        "http://example.com",
        "example.com",
        "127.0.0.1",
        "bad; rm -rf /",
        "https://localhost/path?q=1",
    ]
    for t in tests:
        ok, msg = ping_url(t)
        print(f"Input: {t} -> {msg}")
    # Start server if Flask is available
    if FLASK_AVAILABLE:
        print("Server on http://127.0.0.1:5000/ping?url=example.com")
        app.run(host="127.0.0.1", port=5000, debug=False)