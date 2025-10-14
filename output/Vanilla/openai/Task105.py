import socket, ssl

def connect_tls(host: str, port: int, timeout_seconds: float = 8.0) -> str:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                try:
                    cert = ssock.getpeercert()
                except ssl.SSLError:
                    cert = None

                cipher = ssock.cipher()[0] if ssock.cipher() else ""
                proto = ssock.version() or ""
                subject = ""
                issuer = ""
                if cert:
                    # Extract CN from subject
                    try:
                        subject_parts = cert.get("subject", [])
                        for rdn in subject_parts:
                            for k, v in rdn:
                                if k == "commonName":
                                    subject = v
                                    break
                            if subject:
                                break
                    except Exception:
                        subject = ""
                    try:
                        issuer_parts = cert.get("issuer", [])
                        for rdn in issuer_parts:
                            for k, v in rdn:
                                if k == "organizationName":
                                    issuer = v
                                    break
                            if issuer:
                                break
                    except Exception:
                        issuer = ""
                return f"OK {host}:{port} protocol={proto} cipher={cipher} subject={subject} issuer={issuer}"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"

if __name__ == "__main__":
    tests = [
        ("www.google.com", 443),
        ("www.cloudflare.com", 443),
        ("www.github.com", 443),
        ("www.stackoverflow.com", 443),
        ("expired.badssl.com", 443),
    ]
    for h, p in tests:
        print(connect_tls(h, p, 8.0))