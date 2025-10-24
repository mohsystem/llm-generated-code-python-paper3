import ssl
import http.client
import urllib.parse
import socket
import hashlib
import hmac
from typing import Optional, Tuple, Dict, List


class InvalidURLError(Exception):
    pass


class TLSConnectionError(Exception):
    pass


class CertificatePinningError(Exception):
    pass


def _normalize_hex(hex_str: str) -> str:
    return "".join(c for c in hex_str.lower() if c.isalnum())


def create_secure_context(
    cafile: Optional[str] = None,
    capath: Optional[str] = None,
    cadata: Optional[str] = None,
    minimum_tls: str = "1.2",
) -> ssl.SSLContext:
    """
    Create a secure SSLContext enforcing TLS 1.2+ with hostname verification and CA validation.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile, capath=capath, cadata=cadata)
    # Enforce certificate validation and hostname checking
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True

    # Enforce TLS 1.2 or higher
    if hasattr(ssl, "TLSVersion"):
        if minimum_tls not in ("1.2", "1.3"):
            raise ValueError("minimum_tls must be '1.2' or '1.3'")
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2 if minimum_tls == "1.2" else ssl.TLSVersion.TLSv1_3
        # Let OpenSSL negotiate the max supported version (typically up to TLS 1.3)
        if hasattr(ssl.TLSVersion, "MAXIMUM_SUPPORTED"):
            ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    else:
        # Best-effort hardening for very old Python
        ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)

    return ctx


def _validate_hostname(hostname: str) -> None:
    if not hostname or len(hostname) > 253:
        raise InvalidURLError("Invalid host length")
    # Basic validation: allow IPv6 in brackets, IPv4, or domain labels
    if hostname.startswith("[") and hostname.endswith("]"):
        # IPv6 literal; rough check
        inner = hostname[1:-1]
        if not inner or any(c for c in inner if not (c.isalnum() or c in ":.")):
            raise InvalidURLError("Invalid IPv6 literal")
    else:
        # Domain or IPv4
        labels = hostname.split(".")
        for label in labels:
            if not label or len(label) > 63:
                raise InvalidURLError("Invalid DNS label")
            if not (label[0].isalnum() and label[-1].isalnum()):
                raise InvalidURLError("DNS label must start/end with alnum")
            for ch in label:
                if not (ch.isalnum() or ch == "-"):
                    raise InvalidURLError("Invalid character in DNS label")


def _parse_https_url(url: str) -> Tuple[str, int, str]:
    """
    Parse an HTTPS URL and return (hostname, port, path_with_query).
    """
    if not isinstance(url, str) or len(url) > 2048:
        raise InvalidURLError("URL must be a string of reasonable length")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise InvalidURLError("Only https scheme is allowed")
    if not parsed.hostname:
        raise InvalidURLError("URL must include a hostname")
    host = parsed.hostname
    _validate_hostname(host)

    port = parsed.port if parsed.port is not None else 443
    if not (1 <= port <= 65535):
        raise InvalidURLError("Port out of range")

    path = parsed.path or "/"
    if len(path) > 2000:
        raise InvalidURLError("Path too long")
    query = f"?{parsed.query}" if parsed.query else ""
    full_path = f"{path}{query}"
    return host, port, full_path


def _read_limited(response: http.client.HTTPResponse, max_bytes: int) -> bytes:
    """
    Safely read up to max_bytes from the response body.
    """
    if max_bytes <= 0 or max_bytes > 50_000_000:
        raise ValueError("max_bytes must be between 1 and 50,000,000")
    chunks: List[bytes] = []
    total = 0
    chunk_size = 8192
    while True:
        to_read = min(chunk_size, max_bytes - total)
        if to_read <= 0:
            # If server keeps sending beyond the limit, refuse
            raise TLSConnectionError("Response exceeded allowed size")
        data = response.read(to_read)
        if not data:
            break
        chunks.append(data)
        total += len(data)
        if total >= max_bytes:
            # If there might be more data, fail closed rather than truncating silently
            # Attempt a non-blocking read to see if more data exists
            break
    # If server still has pending data but we reached the limit, treat as error
    if total >= max_bytes:
        # Try to peek a byte without advancing if possible; otherwise, conservatively error
        raise TLSConnectionError("Response exceeded allowed size")
    return b"".join(chunks)


def _get_peer_cert_sha256_hex(conn: http.client.HTTPSConnection) -> str:
    """
    Return the SHA-256 fingerprint (hex) of the peer leaf certificate (DER).
    """
    sock = getattr(conn, "sock", None)
    if sock is None or not hasattr(sock, "getpeercert"):
        raise TLSConnectionError("TLS socket not available for certificate retrieval")
    cert_der: Optional[bytes] = sock.getpeercert(binary_form=True)  # type: ignore[call-arg]
    if not cert_der:
        raise TLSConnectionError("Peer certificate not available")
    digest = hashlib.sha256(cert_der).hexdigest()
    return _normalize_hex(digest)


def https_get(
    url: str,
    timeout: float = 10.0,
    max_bytes: int = 1_000_000,
    ctx: Optional[ssl.SSLContext] = None,
    pinned_cert_sha256: Optional[str] = None,
    allow_redirects: bool = True,
    max_redirects: int = 3,
    user_agent: str = "SecureTLSClient/1.0",
) -> Tuple[int, Dict[str, str], bytes]:
    """
    Perform an HTTPS GET with strict TLS settings, optional certificate pinning, and safe reads.
    Returns (status_code, headers, body_bytes).
    """
    if not (0.1 <= timeout <= 120.0):
        raise ValueError("timeout out of range")
    if max_redirects < 0 or max_redirects > 10:
        raise ValueError("max_redirects out of range")

    redirects = 0
    current_url = url

    while True:
        host, port, path = _parse_https_url(current_url)
        context = ctx or create_secure_context()

        conn = None
        try:
            conn = http.client.HTTPSConnection(host=host, port=port, timeout=timeout, context=context)
            headers = {
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Connection": "close",
            }
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()

            # Optional certificate pinning
            if pinned_cert_sha256:
                expected = _normalize_hex(pinned_cert_sha256)
                observed = _get_peer_cert_sha256_hex(conn)
                if not hmac.compare_digest(expected, observed):
                    raise CertificatePinningError("Pinned certificate SHA-256 mismatch")

            status = resp.status
            # Handle redirects securely (HTTPS->HTTPS only)
            if allow_redirects and status in (301, 302, 303, 307, 308):
                if redirects >= max_redirects:
                    raise TLSConnectionError("Too many redirects")
                loc = resp.getheader("Location")
                if not loc:
                    raise TLSConnectionError("Redirect with no Location header")
                # Resolve relative redirects
                current_url = urllib.parse.urljoin(current_url, loc)
                # Enforce https only
                parsed_next = urllib.parse.urlsplit(current_url)
                if parsed_next.scheme.lower() != "https":
                    raise TLSConnectionError("Refusing to follow non-HTTPS redirect")
                redirects += 1
                # Close the current connection before looping
                try:
                    resp.close()
                finally:
                    conn.close()
                continue

            # Collect headers into a simple dict (last value wins)
            headers_out: Dict[str, str] = {}
            for k, v in resp.getheaders():
                # sanitize header names/values to avoid control chars
                if k and v and "\r" not in k and "\n" not in k and "\r" not in v and "\n" not in v:
                    headers_out[k] = v

            body = _read_limited(resp, max_bytes)
            return status, headers_out, body

        except (ssl.SSLError, socket.timeout, socket.gaierror, ConnectionError) as e:
            raise TLSConnectionError(f"TLS/Network error: {type(e).__name__}") from e
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass


def main() -> None:
    tests = [
        # 1) Simple HTTPS GET (expected: success)
        "https://www.example.com/",
        # 2) Large provider (expected: success or redirect handled by server)
        "https://www.wikipedia.org/",
        # 3) Likely redirect to localized domain (expected: success with possible redirect)
        "https://www.google.com/",
        # 4) Invalid scheme (expected: fail closed)
        "http://www.example.com/",
        # 5) Invalid port in URL (expected: fail closed)
        "https://www.example.com:70000/",
    ]

    ctx = create_secure_context(minimum_tls="1.2")

    for i, url in enumerate(tests, start=1):
        print(f"Test {i}: GET {url}")
        try:
            status, headers, body = https_get(url, timeout=10.0, max_bytes=200_000, ctx=ctx, allow_redirects=True)
            cl = headers.get("Content-Length", "unknown")
            print(f"  -> Status: {status}, Bytes: {len(body)}, Reported-Content-Length: {cl}")
        except (InvalidURLError, TLSConnectionError, CertificatePinningError, ValueError) as e:
            print(f"  -> Failed: {e.__class__.__name__}")
        except Exception as e:
            # Fail closed with minimal info
            print(f"  -> Failed: UnexpectedError")

    # Optional: Demonstrate certificate pinning mismatch (expected: fail)
    try:
        print("Test 6: Certificate pinning mismatch demonstration")
        wrong_pin = "00" * 32  # deliberately incorrect SHA-256
        _ = https_get("https://www.example.com/", pinned_cert_sha256=wrong_pin, max_bytes=100_000)
        print("  -> Unexpected success (should have failed)")
    except CertificatePinningError:
        print("  -> Failed as expected: CertificatePinningError")
    except Exception:
        print("  -> Failed with other error (environment-dependent)")


if __name__ == "__main__":
    main()