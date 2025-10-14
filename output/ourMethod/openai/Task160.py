import sys
import socket
import ssl
from typing import Tuple
from urllib.parse import urlsplit, urlunsplit
from urllib.request import build_opener, HTTPSHandler, HTTPHandler, Request
from urllib.error import URLError, HTTPError
import ipaddress

MAX_URL_LENGTH = 2048
CONNECT_TIMEOUT = 10
MAX_BODY_BYTES = 1024 * 1024  # 1 MiB

def fetch_url_safely(raw_url: str) -> str:
    try:
        url = validate_and_normalize_url(raw_url)
        scheme, netloc, path, query, fragment = urlsplit(url)
        host = netloc.split('@')[-1]
        host_no_port = host
        if host.startswith('['):
            # IPv6 literal in brackets
            end = host.find(']')
            if end == -1:
                raise ValueError("Invalid IPv6 literal")
            host_no_port = host[1:end]
        else:
            if ':' in host:
                host_no_port = host.rsplit(':', 1)[0]

        if not is_host_public_and_routable(host_no_port):
            return "ERROR: Host resolves to a private, loopback, link-local, multicast, or unspecified address"

        # SSL context with default verification (hostname + CA)
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        # No redirects for SSRF safety
        class NoRedirect(HTTPHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        opener = build_opener(NoRedirect, HTTPHandler(), HTTPSHandler(context=context))
        req = Request(url=url, method='GET', headers={
            'User-Agent': 'Task160-Client/1.0',
            'Accept-Encoding': 'identity'
        })

        with opener.open(req, timeout=CONNECT_TIMEOUT) as resp:
            status = getattr(resp, 'status', getattr(resp, 'code', 0))
            headers = ''.join([f"  {k}: {v}\n" for k, v in resp.headers.items()])
            body_chunks = []
            total = 0
            while True:
                chunk = resp.read(min(65536, MAX_BODY_BYTES - total))
                if not chunk:
                    break
                body_chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_BODY_BYTES:
                    break
            body = b''.join(body_chunks)
            text = body.decode('utf-8', errors='replace')
            if total >= MAX_BODY_BYTES:
                text += f"\n[Truncated to {MAX_BODY_BYTES} bytes]"
            return f"STATUS: {status}\nHEADERS:\n{headers}BODY:\n{text}"
    except (ValueError) as ve:
        return f"ERROR: {safe_message(ve)}"
    except HTTPError as he:
        try:
            body = he.read(MAX_BODY_BYTES).decode('utf-8', errors='replace')
        except Exception:
            body = ""
        return f"STATUS: {he.code}\nHEADERS:\n{''.join([f'  {k}: {v}\n' for k, v in he.headers.items()])}BODY:\n{body}"
    except URLError as ue:
        return f"ERROR: {safe_message(ue)}"
    except Exception as e:
        return f"ERROR: {safe_message(e)}"

def validate_and_normalize_url(raw_url: str) -> str:
    if raw_url is None:
        raise ValueError("URL is null")
    raw_url = raw_url.strip()
    if len(raw_url) == 0 or len(raw_url) > MAX_URL_LENGTH:
        raise ValueError("URL length is invalid")

    parts = urlsplit(raw_url)
    scheme = parts.scheme.lower()
    if scheme not in ('http', 'https'):
        raise ValueError("Only http and https schemes are allowed")
    if not parts.netloc:
        raise ValueError("Missing host")
    if '@' in parts.netloc:
        raise ValueError("Credentials in URL are not allowed")

    # Validate port if present
    host_port = parts.netloc
    host_only = host_port
    if host_port.startswith('['):
        end = host_port.find(']')
        if end == -1:
            raise ValueError("Invalid IPv6 literal")
        rest = host_port[end+1:]
        if rest.startswith(':'):
            port_str = rest[1:]
            if not port_str.isdigit():
                raise ValueError("Invalid port")
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError("Invalid port")
    else:
        if ':' in host_port:
            host_only, port_str = host_port.rsplit(':', 1)
            if port_str:
                if not port_str.isdigit():
                    raise ValueError("Invalid port")
                port = int(port_str)
                if port < 1 or port > 65535:
                    raise ValueError("Invalid port")

    normalized = urlunsplit((scheme, parts.netloc, parts.path or '/', parts.query, parts.fragment))
    return normalized

def is_host_public_and_routable(host: str) -> bool:
    try:
        # Resolve all addresses and ensure each is public/routable
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        if not infos:
            return False
        for family, _, _, _, sockaddr in infos:
            ip_str = None
            if family == socket.AF_INET:
                ip_str = sockaddr[0]
            elif family == socket.AF_INET6:
                ip_str = sockaddr[0]
            else:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                return False
            if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
                ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
                return False
        return True
    except Exception:
        return False

def safe_message(e: Exception) -> str:
    msg = str(e) if e else e.__class__.__name__
    if msg is None or msg == "":
        msg = e.__class__.__name__
    if len(msg) > 300:
        msg = msg[:300]
    return msg

if __name__ == "__main__":
    tests = [
        "https://example.com",
        "http://example.com",
        "ftp://example.com",
        "http://127.0.0.1",
        "http://user:pass@example.com"
    ]
    for t in tests:
        print("URL:", t)
        print(fetch_url_safely(t))
        print("----")