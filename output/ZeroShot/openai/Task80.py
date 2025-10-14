import socket
import ssl
from typing import Optional

def create_ipv6_ssl_socket(host: str, port: int, timeout: float = 10.0) -> ssl.SSLSocket:
    if not host or not isinstance(host, str) or not (0 < port < 65536):
        raise ValueError("Invalid host or port")
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # enforce modern TLS
    except Exception:
        pass

    # Resolve IPv6 addresses only
    infos = socket.getaddrinfo(host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    last_err: Optional[Exception] = None
    for family, socktype, proto, canonname, sockaddr in infos:
        try:
            raw = socket.socket(family, socktype, proto)
            try:
                raw.settimeout(timeout)
                raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                raw.connect(sockaddr)
                ssock = ctx.wrap_socket(raw, server_hostname=host)
                return ssock
            except Exception:
                raw.close()
                raise
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise OSError("No IPv6 addresses found or failed to connect")

if __name__ == "__main__":
    tests = [
        ("ipv6.google.com", 443),
        ("www.cloudflare.com", 443),
        ("www.google.com", 443),
        ("www.wikipedia.org", 443),
        ("www.youtube.com", 443),
    ]
    for h, p in tests:
        s = None
        try:
            s = create_ipv6_ssl_socket(h, p, timeout=8.0)
            print(f"Connected to {h} via IPv6, cipher={s.cipher()}")
        except Exception as e:
            print(f"Failed to connect to {h}: {e}")
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass