import socket
import ssl
from typing import Optional

def create_ipv6_tls_client(host: str, port: int, timeout: float) -> ssl.SSLSocket:
    if not isinstance(host, str) or not host:
        raise ValueError("host must be a non-empty string")
    if not (1 <= int(port) <= 65535):
        raise ValueError("port must be in 1..65535")
    if not (0 < float(timeout) <= 60.0):
        raise ValueError("timeout must be in (0, 60] seconds")

    # Resolve IPv6 addresses only
    infos = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
    if not infos:
        raise socket.gaierror(f"No IPv6 address found for host: {host}")

    raw_sock: Optional[socket.socket] = None
    try:
        raw_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        addr = infos[0][4]  # First IPv6 address (addr, port, flowinfo, scopeid)
        raw_sock.connect(addr)

        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers("HIGH:!aNULL:!MD5:!RC4")
        except ssl.SSLError:
            # If cipher configuration unsupported, proceed with platform defaults
            pass

        # SNI and hostname verification use 'server_hostname'
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        # At this point handshake is done and certificate validated
        return tls_sock
    except Exception:
        if raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass
        raise

def _close_quietly(s: Optional[ssl.SSLSocket]) -> None:
    if s:
        try:
            s.close()
        except Exception:
            pass

if __name__ == "__main__":
    tests = [
        ("google.com", 443, 4.0),
        ("cloudflare.com", 443, 4.0),
        ("wikipedia.org", 443, 4.0),
        ("ietf.org", 443, 4.0),
        ("facebook.com", 443, 4.0),
    ]
    for host, port, to in tests:
        s = None
        try:
            print(f"Connecting (IPv6/TLS) to {host}:{port}")
            s = create_ipv6_tls_client(host, port, to)
            cipher = s.cipher()
            print(f"Success: {host} - Protocol={s.version()}, Cipher={cipher[0] if cipher else 'unknown'}")
        except Exception as e:
            print(f"Failed: {host} - {type(e).__name__}: {e}")
        finally:
            _close_quietly(s)