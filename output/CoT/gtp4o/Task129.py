import re
import socket
import ssl
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
import ipaddress

SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

def _is_safe_filename(name: str) -> bool:
    if not isinstance(name, str):
        return False
    if not SAFE_FILENAME.fullmatch(name):
        return False
    if ".." in name:
        return False
    return True

def _is_safe_base_url(base_url: str) -> bool:
    try:
        parsed = urlparse(base_url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.hostname:
        return False
    # Resolve and validate IPs
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), 0, socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    seen_ips = set()
    for info in infos:
        ip = info[4][0]
        # Strip IPv6 zone index if any
        if "%" in ip:
            ip = ip.split("%", 1)[0]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False
    return True

def retrieve_file_from_server(base_url: str, file_name: str) -> bytes:
    if not _is_safe_base_url(base_url):
        raise ValueError("Invalid or unsafe base URL")
    if not _is_safe_filename(file_name):
        raise ValueError("Invalid file name")

    parsed = urlparse(base_url)
    # Construct URL safely; only safe characters allowed in filename so direct append is fine
    target = urljoin(base_url if base_url.endswith("/") else base_url + "/", f"files/{file_name}")

    req = Request(target, headers={
        "User-Agent": "Task129/1.0",
        "Accept": "application/octet-stream"
    })

    # Enforce HTTPS certificate verification by default; timeout set
    with urlopen(req, timeout=15) as resp:
        status = getattr(resp, "status", None) or resp.getcode()
        if status != 200:
            raise RuntimeError(f"HTTP error: {status}")

        cl = resp.getheader("Content-Length")
        if cl:
            try:
                length = int(cl)
                if length < 0 or length > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError("Content too large")
            except ValueError:
                pass

        chunks = []
        total = 0
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise RuntimeError("Download exceeded size limit")
            chunks.append(chunk)
        return b"".join(chunks)

if __name__ == "__main__":
    tests = [
        ("https://example.com", "document.txt"),
        ("https://example.com", "image-file_01.png"),
        ("https://example.com", "..bad.txt"),         # invalid
        ("https://example.com", "notes..txt"),        # invalid
        ("https://example.com", "really_really_long-name.v1.2.3.tar.gz"),
    ]
    for base, fn in tests:
        try:
            data = retrieve_file_from_server(base, fn)
            print(f"OK: {fn} size={len(data)}")
        except Exception as e:
            print(f"ERR: {fn} -> {e}")