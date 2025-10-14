import socket
import ssl
import sys
from typing import Optional

# Chain-of-Through process (high-level):
# 1) Implement IPv6 TCP SSL client function.
# 2) Enforce certificate/hostname verification and SNI.
# 3) Use secure TLS versions and timeouts.
# 4) Review for proper resource management.
# 5) Provide final secure function and tests.

def create_ipv6_ssl_client(host: str, port: int) -> ssl.SSLSocket:
    if not host or not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("Invalid host or port")

    # Resolve IPv6 addresses only
    infos = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    if not infos:
        raise socket.gaierror(f"No IPv6 address found for host: {host}")

    af, socktype, proto, _, sockaddr = infos[0]
    s = socket.socket(af, socktype, proto)
    try:
        # Enforce IPv6-only, where supported
        try:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except OSError:
            pass  # Platform may not support changing this setting

        s.settimeout(10.0)
        s.connect(sockaddr)

        # Secure SSL context
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        # Enforce modern TLS
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Wrap with SNI and perform handshake
        ssock = ctx.wrap_socket(s, server_hostname=host)
        # Handshake occurs on first I/O; force it to catch errors early
        ssock.do_handshake()
        return ssock
    except Exception:
        s.close()
        raise

if __name__ == "__main__":
    tests = [
        ("google.com", 443),
        ("cloudflare.com", 443),
        ("example.com", 443),
        ("ietf.org", 443),
        ("wikipedia.org", 443),
    ]
    for host, port in tests:
        print(f"Connecting to {host} over IPv6 TLS...")
        try:
            ssock = create_ipv6_ssl_client(host, port)
            try:
                cipher = ssock.cipher()
                version = ssock.version()
                peer = ssock.getpeername()
                print(f"Connected: {peer}, TLS: {version}, Cipher: {cipher[0] if cipher else 'N/A'}")
            finally:
                ssock.close()
        except Exception as e:
            print(f"Failed to connect to {host}: {e}")
        print("----")