import socket
import ssl
from typing import Optional, Tuple


def create_ssl_ipv6_client(host: str, port: int, timeout: Optional[float] = 10.0) -> ssl.SSLSocket:
    """
    Create an SSL/TLS client socket over IPv6 and TCP, connect to the specified host and port,
    and return the established SSL socket.

    Args:
        host: The DNS hostname or IPv6 address to connect to. Bracketed IPv6 literals like "[::1]" are accepted.
        port: The TCP port number (1-65535).
        timeout: Optional timeout in seconds for socket operations.

    Returns:
        An established ssl.SSLSocket connected to the server.

    Raises:
        ValueError: If inputs are invalid.
        ConnectionError: If connection fails for all resolved IPv6 addresses.
        ssl.SSLError: If the TLS handshake fails.
    """
    if not isinstance(host, str) or not host.strip():
        raise ValueError("Host must be a non-empty string.")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("Port must be an integer in the range 1..65535.")
    if timeout is not None:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("Timeout must be a positive number or None.")

    # Normalize bracketed IPv6 literals like "[2001:db8::1]"
    normalized_host = host.strip()
    if normalized_host.startswith('[') and normalized_host.endswith(']'):
        normalized_host = normalized_host[1:-1]

    # Secure default SSL context with certificate validation and hostname checking
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Enforce TLS 1.2+
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        # Disable insecure protocol versions on older Python
        ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
    # Disable compression (mitigate CRIME)
    ctx.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)

    # Resolve IPv6 addresses only
    try:
        addrinfo = socket.getaddrinfo(
            normalized_host,
            port,
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as e:
        raise ConnectionError(f"DNS resolution for IPv6 failed for host '{host}': {e}") from e

    last_error: Optional[BaseException] = None
    for family, socktype, proto, _canonname, sockaddr in addrinfo:
        raw_sock: Optional[socket.socket] = None
        try:
            raw_sock = socket.socket(family, socktype, proto)
            if timeout is not None:
                raw_sock.settimeout(timeout)
            # Optional but generally beneficial socket options
            try:
                raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                # Some platforms may not support TCP_NODELAY on IPv6 sockets
                pass
            try:
                raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except OSError:
                pass

            # sockaddr for IPv6 is (addr, port, flowinfo, scopeid)
            raw_sock.connect(sockaddr)

            # Wrap with SSL, enforce SNI and hostname verification
            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=normalized_host)
            # Ownership transferred to ssl_sock; avoid closing raw_sock separately
            return ssl_sock
        except (OSError, ssl.SSLError) as e:
            last_error = e
            # Ensure cleanup of raw socket if wrap failed or connect failed
            if raw_sock is not None:
                try:
                    raw_sock.close()
                except OSError:
                    pass
            continue

    if last_error:
        raise ConnectionError(f"Failed to establish IPv6 TLS connection to {host}:{port}") from last_error
    raise ConnectionError(f"No IPv6 addresses found for {host}:{port}")


def _run_test_case(host: str, port: int) -> Tuple[bool, str]:
    """
    Run a single test case attempting to connect and return (success, message).
    """
    try:
        s = create_ssl_ipv6_client(host, port, timeout=5.0)
        try:
            cipher = s.cipher()
            tls_version = s.version()
            peer = s.getpeername()
            return True, f"Connected to {host}:{port} | TLS={tls_version} | Cipher={cipher[0]} | Peer={peer}"
        finally:
            s.close()
    except Exception as e:
        return False, f"Failed to connect to {host}:{port} | {e.__class__.__name__}: {e}"


def main() -> None:
    # Five test cases (IPv6-capable public hosts). Success depends on environment IPv6 connectivity.
    tests = [
        ("google.com", 443),
        ("cloudflare.com", 443),
        ("www.wikipedia.org", 443),
        ("www.ietf.org", 443),
        ("ipv6.google.com", 443),
    ]
    for host, port in tests:
        ok, msg = _run_test_case(host, port)
        print(("OK: " if ok else "ERROR: ") + msg)


if __name__ == "__main__":
    main()