import os
import platform
import re
import subprocess
import sys
from urllib.parse import urlparse

# Simple route registry using a decorator
_ROUTES = {}

def route(path):
    def deco(func):
        _ROUTES[path] = func
        return func
    return deco

def _extract_host_ascii(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url is empty")
    u = url.strip()
    # Allow schemeless
    parsed = urlparse(u if "://" in u else f"//{u}", scheme="")
    host = parsed.hostname
    if not host:
        raise ValueError("No host found in URL")
    try:
        host_idna = host.encode("idna").decode("ascii")
    except Exception as e:
        raise ValueError(f"IDNA conversion failed: {e}")
    if not re.fullmatch(r"[A-Za-z0-9\-\.\:]+", host_idna):
        raise ValueError("Host contains invalid characters")
    if len(host_idna) > 253:
        raise ValueError("Host too long")
    return host_idna

def safe_ping(url: str):
    host = _extract_host_ascii(url)
    is_windows = platform.system().lower().startswith("win")
    if is_windows:
        cmd = ["ping", "-n", "1", "-w", "2000", host]
    else:
        # -W is in seconds on Linux, ms on macOS; 2 is fine for both
        cmd = ["ping", "-c", "1", "-W", "2", host]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        pong = (proc.stdout or "") + (proc.stderr or "")
        alive = (proc.returncode == 0)
        return {"alive": alive, "pong": pong, "host": host}
    except subprocess.TimeoutExpired:
        return {"alive": False, "pong": "Timeout executing ping", "host": host}
    except Exception as e:
        return {"alive": False, "pong": f"Error executing ping: {e}", "host": host}

@route("/ping")
def ping(params: dict):
    # The variable 'url' holds the URL to ping
    if not isinstance(params, dict) or "url" not in params:
        return {"alive": False, "pong": "Missing 'url' parameter", "host": None}
    url = params["url"]
    result = safe_ping(url)
    pong = result.get("pong", "")
    # 'pong' variable storing output
    return {"alive": bool(result.get("alive")), "pong": pong, "host": result.get("host")}

def handle_request(path: str, params: dict):
    if path in _ROUTES:
        return _ROUTES[path](params)
    return {"error": "not found"}

def main():
    tests = [
        {"url": "https://example.com"},
        {"url": "example.com"},
        {"url": "8.8.8.8"},
        {"url": "http://[::1]"},
        {"url": "invalid host!!"}
    ]
    for t in tests:
        res = handle_request("/ping", t)
        # Print minimal info to avoid huge outputs
        print(f"Test {t['url']} -> alive={res.get('alive')} host={res.get('host')} pongLen={len(res.get('pong',''))}")

if __name__ == "__main__":
    main()