# Steps 1-5: Problem understanding, security requirements, secure generation, review, secure output (summarized)
from urllib.parse import urlsplit
import ipaddress
import re

def is_valid_url(url: str) -> bool:
    if not isinstance(url, str):
        return False
    s = url.strip()
    if len(s) == 0 or len(s) > 2048:
        return False
    if any(ch.isspace() for ch in s) or any(ord(ch) < 32 for ch in s):
        return False

    try:
        parts = urlsplit(s)
    except Exception:
        return False

    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False

    # Disallow userinfo
    if parts.username is not None or parts.password is not None:
        return False

    host = parts.hostname
    if not host:
        return False

    # Port validation
    try:
        if parts.port is not None and (parts.port < 1 or parts.port > 65535):
            return False
    except ValueError:
        return False

    if not is_valid_host(host):
        return False

    return True

def is_valid_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    # IP literal check
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return is_valid_domain(host)

def is_valid_domain(host: str) -> bool:
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except Exception:
        return False
    if len(ascii_host) == 0 or len(ascii_host) > 253:
        return False
    labels = ascii_host.split(".")
    label_re = re.compile(r"^[A-Za-z0-9-]+$")
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if not label_re.match(label):
            return False
    return True

if __name__ == "__main__":
    tests = [
        "https://example.com",
        "http://sub.example.co.uk:8080/path?query=1#frag",
        "ftp://example.com",
        "https://user:pass@example.com",
        "http://-bad.com",
    ]
    for t in tests:
        print(f"{t} -> {is_valid_url(t)}")