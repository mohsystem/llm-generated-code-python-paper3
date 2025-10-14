import socket
import ssl
from typing import Optional

def https_get(host: str, port: int, path: str, timeout: Optional[float] = 10.0) -> str:
    if not host:
        raise ValueError("host is required")
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    if port <= 0:
        port = 443

    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    # Enforce hostname checking and certificate verification
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # Enforce minimum TLS version
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Task105-Python/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            ssock.sendall(req.encode("utf-8"))
            # Read status line
            file = ssock.makefile("r", encoding="utf-8", newline="\n")
            status_line = file.readline().rstrip("\r\n")
            if not status_line:
                raise IOError("No response received")
            return status_line

if __name__ == "__main__":
    tests = [
        ("www.google.com", 443, "/"),
        ("www.github.com", 443, "/"),
        ("www.cloudflare.com", 443, "/"),
        ("www.wikipedia.org", 443, "/"),
        ("example.com", 443, "/"),
    ]
    for host, port, path in tests:
        try:
            print(host + ": " + https_get(host, port, path, timeout=10.0))
        except Exception as e:
            print(host + ": ERROR - " + str(e))