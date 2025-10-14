import socket
import ssl
from typing import Optional

class Task105:
    @staticmethod
    def establish_secure_connection(host: str, port: int, timeout: float) -> str:
        if not host or not isinstance(host, str):
            return "ERROR: Invalid host"
        if not (1 <= int(port) <= 65535):
            return "ERROR: Invalid port"
        if timeout <= 0:
            return "ERROR: Invalid timeout"

        try:
            context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = True
            # Use default CA certificates; do not disable verification

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    proto = ssock.version()  # e.g., 'TLSv1.3'
                    cipher_info = ssock.cipher()  # tuple(name, protocol, bits)
                    cipher = cipher_info[0] if cipher_info else "unknown"
                    cert = ssock.getpeercert()
                    subject = ""
                    if cert and "subject" in cert:
                        try:
                            subject = ", ".join("=".join(attr) for rdn in cert["subject"] for attr in rdn)
                        except Exception:
                            subject = str(cert.get("subject", ""))
                    return f"OK host={host} port={port} protocol={proto} cipher={cipher} subject=\"{subject}\""
        except Exception as e:
            return f"ERROR: {type(e).__name__}: {str(e)}"


if __name__ == "__main__":
    tests = [
        ("www.google.com", 443, 8.0),
        ("www.cloudflare.com", 443, 8.0),
        ("www.github.com", 443, 8.0),
        ("www.wikipedia.org", 443, 8.0),
        ("api.openai.com", 443, 8.0),
    ]
    for host, port, to in tests:
        print(Task105.establish_secure_connection(host, port, to))