import sys
import json
import socket
import ssl
from urllib.parse import urlparse, urljoin
import urllib.request
import ipaddress

def fetch_json_from_url(url: str, timeout: float = 10.0, max_bytes: int = 5 * 1024 * 1024):
    """
    Fetch JSON from the given URL with security checks and return parsed Python object.
    """
    def is_public_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            # Only allow global addresses
            return ip.is_global
        except ValueError:
            return False

    def assert_safe_url(u: str):
        p = urlparse(u)
        if p.scheme not in ("http", "https"):
            raise ValueError("Only http and https schemes are allowed")
        if not p.hostname:
            raise ValueError("URL host is empty")
        host = p.hostname.lower()
        if host == "localhost":
            raise ValueError("Access to localhost is not allowed")
        # Resolve all addresses and ensure all are global
        try:
            infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise ValueError(f"Could not resolve host: {e}")
        addrs = set()
        for info in infos:
            sockaddr = info[4]
            ip = sockaddr[0]
            addrs.add(ip)
        if not addrs:
            raise ValueError("Could not resolve host to any address")
        for ip in addrs:
            if not is_public_ip(ip):
                raise ValueError(f"Host resolves to a non-public address: {ip}")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ctx))

    current = url
    redirects = 0
    while True:
        if redirects > 5:
            raise RuntimeError("Too many redirects")

        assert_safe_url(current)

        req = urllib.request.Request(
            current,
            headers={
                "User-Agent": "Task64/1.0 (+https://example.com/security)",
                "Accept": "application/json, text/plain;q=0.5, */*;q=0.1",
            },
            method="GET",
        )
        try:
            resp = opener.open(req, timeout=timeout)
            code = getattr(resp, "status", resp.getcode())
            if code == 200:
                length = resp.headers.get("Content-Length")
                if length is not None:
                    try:
                        if int(length) > max_bytes:
                            raise RuntimeError("Content-Length exceeds limit")
                    except ValueError:
                        pass
                total = 0
                chunks = []
                while True:
                    chunk = resp.read(min(8192, max_bytes - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError("Response too large")
                    chunks.append(chunk)
                data = b"".join(chunks)
                text = data.decode("utf-8", errors="strict")
                return json.loads(text)
            elif 300 <= code <= 399:
                # Shouldn't happen due to NoRedirect, but handle just in case
                loc = resp.headers.get("Location")
                if not loc:
                    raise RuntimeError("Redirect without Location header")
                current = urljoin(current, loc)
                redirects += 1
                continue
            else:
                # Read error body to free connection
                try:
                    _ = resp.read(8192)
                except Exception:
                    pass
                raise RuntimeError(f"HTTP error: {code}")
        except urllib.error.HTTPError as e:
            # Handle redirects manually
            if 300 <= e.code <= 399:
                loc = e.headers.get("Location")
                if not loc:
                    raise RuntimeError("Redirect without Location header")
                current = urljoin(current, loc)
                redirects += 1
                continue
            else:
                # Attempt to consume error body
                try:
                    _ = e.read(8192)
                except Exception:
                    pass
                raise

if __name__ == "__main__":
    tests = sys.argv[1:] if len(sys.argv) > 1 else [
        "https://jsonplaceholder.typicode.com/todos/1",
        "https://jsonplaceholder.typicode.com/users/1",
        "https://jsonplaceholder.typicode.com/todos/2",
        "https://api.github.com/",
        "https://httpbin.org/json",
    ]
    for i, u in enumerate(tests[:5], 1):
        print(f"Fetching: {u}")
        try:
            obj = fetch_json_from_url(u)
            print(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
        except Exception as ex:
            print(f"Error: {ex}")
        print("----")