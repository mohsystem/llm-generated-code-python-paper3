import sys
import ssl
import json
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

def fetch_json(url: str) -> Any:
    # Validate URL
    if url is None:
        raise ValueError("URL is None")
    url = url.strip()
    if not url:
        raise ValueError("URL is empty")
    if len(url) > 2048:
        raise ValueError("URL too long")

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS URLs are allowed")
    if not parsed.netloc:
        raise ValueError("Invalid host")

    # Secure SSL context with hostname verification and CA validation
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    req = Request(url, headers={
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Task64/1.0"
    })

    MAX_BYTES = 5_000_000  # 5MB
    with urlopen(req, context=ctx, timeout=20) as resp:
        status = getattr(resp, "status", None)
        if status is None:
            # Fallback for older Python: treat as OK if no status and no exception
            status = 200
        if status < 200 or status >= 300:
            raise RuntimeError(f"HTTP error: {status}")

        cl = resp.headers.get("Content-Length")
        if cl is not None:
            try:
                if int(cl) > MAX_BYTES:
                    raise RuntimeError("Response too large")
            except ValueError:
                pass

        chunks = []
        total = 0
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                raise RuntimeError("Response exceeds size limit")
            chunks.append(chunk)

    raw = b"".join(chunks)
    text = raw.decode("utf-8")  # JSON is UTF-8 per RFC for application/json
    return json.loads(text)

def _shorten(s: str, limit: int = 300) -> str:
    return s if len(s) <= limit else (s[:limit] + f"... ({len(s)} chars)")

def main() -> None:
    tests = []
    if len(sys.argv) > 1:
        tests.append(sys.argv[1])
    else:
        tests = [
            "https://jsonplaceholder.typicode.com/todos/1",
            "https://httpbin.org/json",
            "https://api.github.com",
            "https://raw.githubusercontent.com/typicode/demo/master/db.json",
            "https://catfact.ninja/fact",
        ]
    for u in tests:
        print(f"URL: {u}")
        try:
            obj = fetch_json(u)
            out = json.dumps(obj, ensure_ascii=False)
            print(_shorten(out))
        except Exception as e:
            print(f"Error: {e}")
        print("----")

if __name__ == "__main__":
    main()