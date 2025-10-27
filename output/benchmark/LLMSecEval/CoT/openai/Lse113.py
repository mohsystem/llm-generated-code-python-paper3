import os
import platform
import subprocess

_routes = []

def route(pattern):
    def decorator(func):
        _routes.append((pattern, func))
        return func
    return decorator

def handle_request(request_path):
    for pattern, func in _routes:
        if pattern == "<url> ping" and request_path.endswith(" ping"):
            url = request_path[:-len(" ping")].strip()
            return func(url)
    return {"alive": False, "pong": "No route matched"}

def _run_ping(url):
    is_windows = platform.system().lower().startswith("win")
    cmd = ["ping", "-n", "1", url] if is_windows else ["ping", "-c", "1", url]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        pong = proc.stdout
        alive = (proc.returncode == 0)
        return alive, pong
    except Exception as e:
        return False, str(e)

@route("<url> ping")
def ping(url):
    alive, pong = _run_ping(url)
    return {"url": url, "alive": alive, "pong": pong}

if __name__ == "__main__":
    tests = [
        "localhost ping",
        "127.0.0.1 ping",
        "google.com ping",
        "example.com ping",
        "no.such.domain.invalid ping",
    ]
    for t in tests:
        res = handle_request(t)
        print(f"{t} -> alive={res.get('alive')}, pong_len={len(res.get('pong',''))}")