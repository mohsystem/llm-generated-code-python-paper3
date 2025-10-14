import sys
import urllib.request
import urllib.error

def fetch_url(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Task160/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            status = getattr(resp, "status", 200)
            data = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
            try:
                body = data.decode(charset, errors="replace")
            except Exception:
                body = data.decode("utf-8", errors="replace")
            return f"HTTP {status}\n{body}"
    except urllib.error.HTTPError as he:
        try:
            data = he.read()
            body = data.decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return f"HTTP {he.code}\n{body}"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"

if __name__ == "__main__":
    test_urls = [
        "https://www.example.com/",
        "https://httpbin.org/get",
        "https://jsonplaceholder.typicode.com/todos/1",
        "http://httpstat.us/200",
        "http://httpstat.us/404",
    ]
    for i, u in enumerate(test_urls, 1):
        res = fetch_url(u)
        print(f"=== Test {i}: {u} ===")
        print((res[:500] + "...") if len(res) > 500 else res)
        print()