import os
import re
import subprocess
import sys
from typing import Callable, Dict, Any
from urllib.parse import urlsplit

ROUTES: Dict[str, Callable[[str], Dict[str, Any]]] = {}

def route(path: str):
    def decorator(func: Callable[[str], Dict[str, Any]]):
        ROUTES[path] = func
        return func
    return decorator

MAX_OUTPUT = 8192

def _extract_and_validate_host(url: str) -> str:
    if url is None:
        raise ValueError("invalid url")
    s = url.strip()
    if not s or len(s) > 2048:
        raise ValueError("invalid url")
    host = s
    if "://" in s:
        parts = urlsplit(s)
        host = parts.hostname or ""
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not (1 <= len(host) <= 253):
        raise ValueError("invalid host length")
    if not re.fullmatch(r"[A-Za-z0-9.\-:]+", host):
        raise ValueError("invalid host characters")
    if " " in host or ";" in host or "|" in host or "&" in host or "$" in host or "`" in host or "\\" in host:
        raise ValueError("invalid host characters")
    return host

def ping(url: str) -> Dict[str, Any]:
    try:
        host = _extract_and_validate_host(url)
    except Exception:
        return {"url": url, "pong": "invalid url/host", "alive": False, "exit_code": -1}

    is_windows = os.name == "nt"
    if is_windows:
        cmd = ["ping", "-n", "1", "-w", "2000", host]
    else:
        cmd = ["ping", "-c", "1", "-W", "2", host]

    pong = ""
    exit_code = -1
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5
        )
        out = proc.stdout or ""
        if len(out) > MAX_OUTPUT:
            pong = out[:MAX_OUTPUT]
        else:
            pong = out
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        pong = "timeout"
        exit_code = -1
    except Exception:
        pong = "error"
        exit_code = -1

    alive = (exit_code == 0)
    return {"url": url, "pong": pong, "alive": alive, "exit_code": exit_code}

@route("/ping")
def ping_handler(url: str) -> Dict[str, Any]:
    return ping(url)

def handle_request(path: str, url: str) -> Dict[str, Any]:
    func = ROUTES.get(path)
    if not func:
        return {"url": url, "pong": "route not found", "alive": False, "exit_code": -1}
    try:
        return func(url)
    except Exception:
        return {"url": url, "pong": "handler error", "alive": False, "exit_code": -1}

if __name__ == "__main__":
    tests = [
        "127.0.0.1",
        "localhost",
        "https://example.com",
        "invalid host!!",
        "8.8.8.8",
    ]
    for t in tests:
        res = handle_request("/ping", t)
        print(f"url={res['url']}, alive={res['alive']}, exit_code={res['exit_code']}, pong_len={len(res['pong'])}")
        sample = res["pong"][:120] + ("..." if len(res["pong"]) > 120 else "")
        print("Sample of pong:", sample)
        print("-----")