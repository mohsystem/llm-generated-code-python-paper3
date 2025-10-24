import sys
import ssl
import socket
import ipaddress
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def _resolve_all_ips(hostname: str, port: Optional[int]) -> List[str]:
    ips: List[str] = []
    try:
        for res in socket.getaddrinfo(hostname, port or 0, type=socket.SOCK_STREAM):
            sockaddr = res[4]
            if len(sockaddr) >= 1:
                ip = sockaddr[0]
                ips.append(ip)
    except socket.gaierror:
        # DNS resolution failed
        return []
    # Deduplicate
    return list(dict.fromkeys(ips))


def _normalize_hostname(hostname: str) -> str:
    # Accept IPv4 or IPv6 literals directly
    try:
        ipaddress.ip_address(hostname)
        return hostname.lower()
    except ValueError:
        pass

    # Normalize FQDN: allow trailing dot but remove it for normalization
    trailing_dot = hostname.endswith(".")
    if trailing_dot:
        hostname = hostname[:-1]

    # IDNA-encode to ASCII
    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except Exception:
        raise ValueError("Invalid hostname (IDNA encoding failed).")

    if len(ascii_host) == 0:
        raise ValueError("Hostname is empty.")

    if len(ascii_host) > 253:
        raise ValueError("Hostname too long.")

    labels = ascii_host.split(".")
    if any(len(lbl) == 0 for lbl in labels):
        raise ValueError("Hostname has empty label.")
    for lbl in labels:
        if len(lbl) > 63:
            raise ValueError("Hostname label too long.")
        # RFC 1035: letters, digits, hyphen, not start or end with hyphen
        for ch in lbl:
            if not (ch.isalnum() or ch == "-"):
                raise ValueError("Hostname contains invalid characters.")
        if lbl[0] == "-" or lbl[-1] == "-":
            raise ValueError("Hostname label cannot start or end with hyphen.")

    return ascii_host.lower()


def validate_and_normalize_url(raw_url: str, max_url_length: int = 2048) -> str:
    if not isinstance(raw_url, str):
        raise ValueError("URL must be a string.")
    url = raw_url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")
    if any(c in url for c in ("\r", "\n")):
        raise ValueError("URL must not contain control characters.")
    if len(url) > max_url_length:
        raise ValueError("URL is too long.")

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only http and https schemes are allowed.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("User info in URL is not allowed.")
    if not parts.hostname:
        raise ValueError("URL must include a hostname.")

    # Normalize hostname and validate
    host_norm = _normalize_hostname(parts.hostname)

    # Validate port if present
    port: Optional[int] = parts.port
    if port is not None:
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535.")

    # Rebuild netloc
    netloc: str
    try:
        # If hostname is IPv6 literal, wrap in brackets
        ipaddress.IPv6Address(host_norm)
        host_for_netloc = f"[{host_norm}]"
    except ValueError:
        host_for_netloc = host_norm

    if port is not None:
        netloc = f"{host_for_netloc}:{port}"
    else:
        netloc = host_for_netloc

    # Remove fragment for safety
    path = parts.path or "/"
    query = parts.query
    if len(path) + len(query) > max_url_length:
        raise ValueError("URL path/query too long.")

    normalized = urlunsplit((scheme, netloc, path, query, ""))

    if len(normalized) > max_url_length:
        raise ValueError("Normalized URL is too long.")

    return normalized


def _extract_safe_headers(hdrs: Any) -> Dict[str, str]:
    # hdrs is an email.message.Message-like object
    wanted = ("Content-Type", "Content-Length", "Date", "Server", "Last-Modified")
    out: Dict[str, str] = {}
    for k in wanted:
        v = hdrs.get(k)
        if v is not None:
            # Ensure no control chars in header values
            sv = str(v).replace("\r", "").replace("\n", "")
            out[k] = sv[:1024]
    return out


def _read_stream(stream: Any, max_bytes: int) -> Tuple[bytes, bool]:
    chunk_size = 16384
    total = 0
    buf = bytearray()
    truncated = False

    while True:
        to_read = min(chunk_size, max_bytes - total)
        if to_read <= 0:
            truncated = True
            break
        chunk = stream.read(to_read)
        if not chunk:
            break
        if not isinstance(chunk, (bytes, bytearray)):
            raise ValueError("Received non-bytes content from stream.")
        buf.extend(chunk)
        total += len(chunk)

    return (bytes(buf), truncated)


def fetch_url_secure(
    url: str,
    timeout: float = 10.0,
    max_bytes: int = 1_000_000,
    allow_private: bool = False,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ok": False,
        "url": "",
        "status_code": None,
        "reason": "",
        "headers": {},
        "body_preview": "",
        "bytes_received": 0,
        "truncated": False,
        "error": "",
    }
    try:
        normalized = validate_and_normalize_url(url)
        result["url"] = normalized

        parts = urlsplit(normalized)
        hostname = parts.hostname
        port = parts.port
        if hostname is None:
            raise ValueError("Hostname missing after normalization.")

        # SSRF protection: disallow private/loopback/etc. addresses
        ips = _resolve_all_ips(hostname, port)
        if not ips:
            raise ValueError("DNS resolution failed.")
        if not allow_private:
            for ip in ips:
                if not _is_public_ip(ip):
                    raise ValueError("Target resolves to a non-public IP address, which is not allowed.")

        # TLS context with strict verification
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        req = Request(
            normalized,
            headers={
                "User-Agent": "SecureUrlFetcher/1.0",
                "Accept": "*/*",
                # Disable compression to avoid zip bombs and ensure precise size limits
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
            method="GET",
        )

        try:
            with urlopen(req, timeout=timeout, context=context) as resp:
                status = getattr(resp, "status", resp.getcode())
                reason = getattr(resp, "reason", "")
                headers = _extract_safe_headers(resp.headers)

                # Early size check if Content-Length is present
                cl = resp.headers.get("Content-Length")
                if cl is not None:
                    try:
                        content_length = int(cl)
                        if content_length < 0:
                            raise ValueError("Negative Content-Length.")
                        if content_length > max_bytes:
                            raise ValueError("Content too large to fetch safely.")
                    except ValueError:
                        # Malformed Content-Length; proceed with chunked reading and limit enforcement
                        pass

                body, truncated = _read_stream(resp, max_bytes)
                preview = body[:2048].decode("utf-8", errors="replace")

                result.update(
                    {
                        "ok": status is not None and 200 <= int(status) < 400,
                        "status_code": int(status) if status is not None else None,
                        "reason": str(reason) if reason is not None else "",
                        "headers": headers,
                        "body_preview": preview,
                        "bytes_received": len(body),
                        "truncated": truncated,
                    }
                )
                return result
        except HTTPError as e:
            # HTTP errors still include response bodies and headers
            status = getattr(e, "code", None)
            reason = getattr(e, "reason", "")
            headers = _extract_safe_headers(getattr(e, "headers", {}))

            # Try to read body safely
            body = b""
            truncated = False
            try:
                body, truncated = _read_stream(e, max_bytes)
            except Exception:
                pass
            finally:
                try:
                    e.close()
                except Exception:
                    pass

            preview = body[:2048].decode("utf-8", errors="replace")

            result.update(
                {
                    "ok": False,
                    "status_code": int(status) if status is not None else None,
                    "reason": str(reason) if reason is not None else "",
                    "headers": headers,
                    "body_preview": preview,
                    "bytes_received": len(body),
                    "truncated": truncated,
                    "error": f"HTTP error {status}",
                }
            )
            return result
    except (ValueError, URLError, ssl.SSLError, socket.timeout, socket.error) as ex:
        msg = str(ex)
        if not msg:
            msg = ex.__class__.__name__
        result["error"] = msg[:512]
        return result
    except Exception as ex:
        # Fail closed with a generic error to avoid leaking details
        result["error"] = "Unexpected error."
        return result


def main() -> None:
    test_cases = [
        # Expected: success
        "https://example.com",
        # Expected: success or redirect; HTTP is allowed but still validated
        "http://httpbin.org/get",
        # Expected: reject due to non-http(s) scheme
        "ftp://example.com/resource",
        # Expected: reject due to private IP (SSRF protection)
        "http://127.0.0.1",
        # Expected: may fail due to size limit if server sends large body
        "https://httpbin.org/bytes/2000000",
    ]

    for i, url in enumerate(test_cases, 1):
        res = fetch_url_secure(url, timeout=10.0, max_bytes=100_000, allow_private=False)
        print(f"Test {i}: {url}")
        print(f"  ok={res['ok']} status={res['status_code']} reason={res['reason']}")
        if res["error"]:
            print(f"  error={res['error']}")
        print(f"  bytes_received={res['bytes_received']} truncated={res['truncated']}")
        print(f"  headers={res['headers']}")
        preview = res["body_preview"]
        if preview:
            print(f"  body_preview={preview[:200].replace(chr(10), ' ')[:200]}")
        print("-" * 60)


if __name__ == "__main__":
    main()