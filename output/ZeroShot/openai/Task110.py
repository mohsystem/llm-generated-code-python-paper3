from urllib.parse import urlsplit
import ipaddress

def is_valid_url(url: str) -> bool:
    if not isinstance(url, str):
        return False
    if len(url) == 0 or len(url) > 2048:
        return False
    for ch in url:
        if ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F:
            return False
    try:
        parts = urlsplit(url)
    except Exception:
        return False
    if parts.scheme.lower() not in ("http", "https"):
        return False
    if not parts.netloc:
        return False
    if "@" in parts.netloc:
        return False  # disallow credentials
    host = parts.hostname
    if not host:
        return False
    # Port validation
    port = parts.port
    if port is not None and (port < 1 or port > 65535):
        return False
    # Host validation: IP or domain (IDN)
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Domain validation with IDNA
    try:
        normalized = host[:-1] if host.endswith(".") else host
        ascii_host = normalized.encode("idna").decode("ascii")
    except Exception:
        return False
    if len(ascii_host) == 0 or len(ascii_host) > 253:
        return False
    labels = ascii_host.split(".")
    for label in labels:
        if len(label) < 1 or len(label) > 63:
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
    return True

if __name__ == "__main__":
    tests = [
        "https://example.com",
        "http://sub.example.co.uk/path?query=1#frag",
        "https://user:pass@example.com",
        "ftp://example.com",
        "http://256.256.256.256",
    ]
    for t in tests:
        print(f"{t} -> {is_valid_url(t)}")