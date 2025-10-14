import ssl
import socket
import urllib.request
import urllib.parse
import ipaddress

MAX_BYTES = 1_048_576  # 1 MiB
TIMEOUT = 10

def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False
        # Explicitly block IPv6 ULA fc00::/7 (handled by is_private in Python 3.9+; ensure here)
        if ip.version == 6 and ip.exploded.startswith(('fc', 'fd')):
            # This check is simplistic; ipaddress handles it generally via is_private
            pass
        return ip.is_global
    except ValueError:
        return False

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
    def http_error_301(self, req, fp, code, msg, headers):
        return fp
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    def http_error_303(self, req, fp, code, msg, headers):
        return fp
    def http_error_307(self, req, fp, code, msg, headers):
        return fp
    def http_error_308(self, req, fp, code, msg, headers):
        return fp

def safe_http_fetch(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in ('http', 'https'):
            return "ERROR: Only http and https schemes are allowed."
        if parsed.username or parsed.password:
            return "ERROR: User info in URL is not allowed."
        host = parsed.hostname
        if not host:
            return "ERROR: URL must include a valid host."
        port = parsed.port
        if port is None:
            port = 80 if scheme == 'http' else 443
        else:
            if (scheme == 'http' and port != 80) or (scheme == 'https' and port != 443):
                return "ERROR: Port not allowed. Only default ports 80 and 443 are permitted."

        # Resolve and validate all IPs
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return "ERROR: Unable to resolve host."
        seen_any = False
        for fam, stype, proto, cname, sockaddr in infos:
            seen_any = True
            ip = sockaddr[0]
            if not _is_public_ip(ip):
                return f"ERROR: Resolved to a private or disallowed IP address: {ip}"
        if not seen_any:
            return "ERROR: No addresses resolved for host."

        headers = {
            "User-Agent": "Task160/1.0 (+https://example.invalid)",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "Range": f"bytes=0-{MAX_BYTES - 1}",
        }
        req = urllib.request.Request(url, headers=headers, method="GET")

        # Disable proxies and redirects; enforce TLS verification
        ctx = ssl.create_default_context()
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ctx),
        )
        try:
            with opener.open(req, timeout=TIMEOUT) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 0))
                if 300 <= status < 400:
                    return f"ERROR: HTTP {status} (redirects are disallowed)"
                if status >= 400:
                    return f"ERROR: HTTP {status}"
                data = resp.read(MAX_BYTES)
                return data.decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            # In case of redirect handler returning response or HTTP errors
            if 300 <= e.code < 400:
                return f"ERROR: HTTP {e.code} (redirects are disallowed)"
            return f"ERROR: HTTP {e.code}"
    except Exception as ex:
        return f"ERROR: {str(ex)}"

if __name__ == "__main__":
    tests = [
        "https://example.com",
        "http://example.com",
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "https://example.com:443",
    ]
    for t in tests:
        print("URL:", t)
        res = safe_http_fetch(t)
        print("Result (first 200 chars):")
        print(res[:200] if res else "")
        print("----")