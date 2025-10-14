import sys
import re
import ssl
import ipaddress
from urllib.parse import urlparse
from urllib.request import Request, urlopen

MAX_BYTES = 1_048_576  # 1 MiB

def fetch_title(url: str) -> str:
    try:
        if not url:
            return ""
        url = url.strip()
        p = urlparse(url)
        if p.scheme.lower() != "https":
            return ""
        host = p.hostname
        if not host:
            return ""
        if host.lower() == "localhost":
            return ""
        try:
            # Block literal IPs
            ipaddress.ip_address(host)
            return ""
        except ValueError:
            pass  # Not a literal IP

        req = Request(url, headers={
            "User-Agent": "Task76/1.0 (+https://example.invalid)",
            "Accept-Encoding": "identity"
        })
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=10, context=ctx) as resp:
            if resp.status != 200:
                return ""
            ctype = resp.headers.get("Content-Type", "")
            charset = "utf-8"
            if "charset=" in ctype.lower():
                try:
                    charset = resp.headers.get_content_charset() or "utf-8"
                except Exception:
                    # Fallback manual parse
                    parts = ctype.split(";")
                    for part in parts:
                        if "charset=" in part.lower():
                            charset = part.split("=", 1)[1].strip().strip("\"'") or "utf-8"
                            break

            data = resp.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                data = data[:MAX_BYTES]
            html = data.decode(charset, errors="replace")

        m = re.search(r"<title\s*[^>]*>(.*?)</title>", html, flags=re.I | re.S)
        if not m:
            return ""
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        return title
    except Exception:
        return ""

if __name__ == "__main__":
    tests = sys.argv[1:] if len(sys.argv) > 1 else [
        "https://example.com",
        "https://httpbin.org/html",
        "https://www.iana.org/domains/reserved",
        "https://www.wikipedia.org",
        "https://www.gnu.org"
    ]
    for u in tests:
        print(f"{u} => {fetch_title(u)}")