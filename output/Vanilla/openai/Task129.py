import urllib.request
import urllib.parse

def fetch_file(base_url: str, path_prefix: str, file_name: str, timeout: float = 10.0) -> str:
    if not path_prefix.startswith("/"):
        path_prefix = "/" + path_prefix
    if not path_prefix.endswith("/"):
        path_prefix = path_prefix + "/"
    encoded = urllib.parse.quote(file_name or "", safe='-_.~')
    path = path_prefix + encoded if encoded else path_prefix.rstrip("/")
    url = urllib.parse.urljoin(base_url, path)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Task129/1.0",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
        try:
            return data.decode(charset, errors="replace")
        except Exception:
            return data.decode("utf-8", errors="replace")

if __name__ == "__main__":
    base_url = "http://example.com"
    prefix = "/"
    files = ["", "robots.txt", "favicon.ico", "nonexisting.file", "index.html"]
    for i, f in enumerate(files, 1):
        try:
            content = fetch_file(base_url, prefix, f, timeout=10.0)
            print(f"Test {i} ({f}): length={len(content)}")
            print(content[:200])
            print("-----")
        except Exception as e:
            print(f"Test {i} ({f}): error={e}")
            print("-----")