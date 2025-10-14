import sys
import re
import gzip
from io import BytesIO
from urllib.request import Request, urlopen

def fetch_title(url: str) -> str:
    try:
        req = Request(
            url,
            headers={
                "User-Agent": "Task76-Python/1.0 (+https://example.com)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip",
                "Connection": "close",
            },
            method="GET",
        )
        with urlopen(req, timeout=20) as resp:
            data = resp.read()
            enc = resp.headers.get("Content-Encoding", "")
            if "gzip" in enc.lower():
                try:
                    data = gzip.decompress(data)
                except Exception:
                    try:
                        data = gzip.GzipFile(fileobj=BytesIO(data)).read()
                    except Exception:
                        pass
            charset = None
            ctype = resp.headers.get("Content-Type", "")
            if "charset=" in ctype.lower():
                for part in ctype.split(";"):
                    if "charset=" in part.lower():
                        charset = part.split("=", 1)[1].strip().strip('"').strip("'")
                        break
            if not charset:
                charset = "utf-8"
            html = data.decode(charset, errors="replace")
            m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
            return m.group(1).strip().replace("\n", " ").replace("\r", " ") if m else ""
    except Exception:
        return ""

def main():
    urls = sys.argv[1:] if len(sys.argv) > 1 else [
        "https://www.example.com/",
        "https://www.wikipedia.org/",
        "https://www.iana.org/domains/reserved",
        "https://www.github.com/",
        "https://www.stackoverflow.com/",
    ]
    for u in urls:
        print(f"{u} => {fetch_title(u)}")

if __name__ == "__main__":
    main()