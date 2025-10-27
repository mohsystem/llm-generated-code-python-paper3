import subprocess
import sys
from typing import Callable, Dict, Any, Optional
from urllib.parse import urlparse
import ipaddress

# Minimal "web app" to demonstrate a decorator mapping URL paths to functions
class MiniApp:
    def __init__(self):
        self.routes: Dict[str, Callable[..., Any]] = {}

    def route(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            self.routes[path] = func
            return func
        return decorator

    def handle_request(self, path: str, query: Dict[str, str]) -> Any:
        handler = self.routes.get(path)
        if not handler:
            return "404 Not Found"
        return handler(query)

app = MiniApp()

def _extract_host(input_url: str) -> Optional[str]:
    if input_url is None:
        return None
    s = input_url.strip()
    if not s or len(s) > 2048:
        return None

    host = None
    try:
        parsed = urlparse(s)
        host = parsed.hostname
        if host is None:
            # handle raw host or bracketed IPv6
            host = s
    except Exception:
        host = s

    if not host:
        return None

    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    return host if host else None

def _is_valid_host(host: str) -> bool:
    if host is None:
        return False
    if len(host) == 0 or len(host) > 253:
        return False
    if host.startswith(".") or host.endswith(".") or host.startswith("-") or host.endswith("-"):
        return False
    if ".." in host:
        return False
    # Allow only safe characters
    for c in host:
        if not (c.isalnum() or c in ".-:"):
            return False
    # If it's an IP literal, validate via ipaddress
    try:
        if ":" in host:
            ipaddress.IPv6Address(host)
            return True
        # Could be IPv4 or hostname
        try:
            ipaddress.IPv4Address(host)
            return True
        except Exception:
            # Not IPv4. Assume hostname; basic label checks
            labels = host.split(".")
            if any(len(lbl) == 0 for lbl in labels):
                return False
            for lbl in labels:
                if len(lbl) > 63:
                    return False
                if not (lbl[0].isalnum() and lbl[-1].isalnum()):
                    return False
                for ch in lbl:
                    if not (ch.isalnum() or ch == '-'):
                        return False
            return True
    except Exception:
        return False

def ping(url: str) -> str:
    host = _extract_host(url)
    if not _is_valid_host(host):
        return "Invalid host"

    is_windows = sys.platform.startswith("win")
    if is_windows:
        cmd = ["ping", "-n", "1", "-w", "1000", host]
    else:
        cmd = ["ping", "-n", "-c", "1", "-W", "1", host]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
            shell=False
        )
        output = (result.stdout or "") + (result.stderr or "")
        if len(output) > 65536:
            output = output[:65536]
        return output
    except subprocess.TimeoutExpired:
        return "Ping timed out"
    except Exception:
        return "Ping failed"

# "Decorator" that maps HTTP path to our handler
@app.route("/ping")
def ping_endpoint(query: Dict[str, str]) -> str:
    # In a real web app, the "url" would come from query parameters.
    url_param = query.get("url", "")
    return ping(url_param)

if __name__ == "__main__":
    tests = [
        "http://127.0.0.1",
        "https://localhost",
        "https://example.com",
        "http://[::1]/",
        "http://bad_host_$$$",
    ]
    for t in tests:
        print(f"=== Test: {t} ===")
        out = app.handle_request("/ping", {"url": t})
        print(out[:500] + ("...(truncated)" if len(out) > 500 else ""))
        print()