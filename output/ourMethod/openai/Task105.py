import socket
import ssl
from typing import Optional


def tls_http_get(host: str, port: int, path: str, timeout_sec: float, max_bytes: int) -> str:
    if not isinstance(host, str) or not host:
        return "ERROR: invalid host"
    if not isinstance(port, int) or port < 1 or port > 65535:
        return "ERROR: invalid port"
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        return "ERROR: invalid max_bytes"
    if not path or not path.startswith("/"):
        path = "/"
    if timeout_sec <= 0:
        timeout_sec = 5.0

    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.options |= ssl.OP_NO_COMPRESSION  # mitigate CRIME
    except Exception:
        pass

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: SecureClient/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii", "strict")

    try:
        with socket.create_connection((host, port), timeout=timeout_sec) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.settimeout(timeout_sec)
                ssock.sendall(request)
                chunks = []
                remaining = max_bytes
                while remaining > 0:
                    to_read = 4096 if remaining > 4096 else remaining
                    data = ssock.recv(to_read)
                    if not data:
                        break
                    chunks.append(data)
                    remaining -= len(data)
                return b"".join(chunks).decode("utf-8", "replace")
    except ssl.SSLError:
        return "ERROR: TLS/SSL failure"
    except (socket.timeout, OSError):
        return "ERROR: network failure"


if __name__ == "__main__":
    tests = [
        ("example.com", 443, "/"),
        ("www.google.com", 443, "/"),
        ("www.cloudflare.com", 443, "/"),
        ("www.github.com", 443, "/"),
        ("www.wikipedia.org", 443, "/"),
    ]
    for host, port, path in tests:
        resp = tls_http_get(host, port, path, 8.0, 2048)
        line = "ERROR: no response"
        if resp and not resp.startswith("ERROR"):
            first_newline = resp.find("\r\n")
            if first_newline > 0:
                line = resp[:first_newline]
            else:
                line = resp[:120]
        else:
            line = resp
        print(f"{host} -> {line}")