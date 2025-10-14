# Chain-of-Through process in code generation:
# 1) Problem understanding: Implement a function that takes a URL string, fetches JSON, parses it, and returns the resulting Python object.
# 2) Security requirements: Validate http/https scheme, set timeouts, limit maximum response size, and decode with proper charset.
# 3) Secure coding generation: Use urllib with timeouts, safe headers, and enforce a size cap before json parsing.
# 4) Code review: Ensure resources are closed, errors handled, and unsafe schemes rejected.
# 5) Secure code output: Final code reflects mitigations and includes 5 test cases.

import sys
import json
import urllib.request
import urllib.parse

def fetch_and_parse_json(url: str):
    if url is None:
        raise ValueError("URL must not be None")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http and https schemes are allowed")

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Task64/1.0 (+https://example.com)",
            "Accept": "application/json, text/json, */*;q=0.8",
        },
        method="GET",
    )

    max_bytes = 5_000_000  # 5 MB safety cap
    timeout = 10  # seconds

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        # Determine charset
        content_type = resp.headers.get("Content-Type", "")
        charset = "utf-8"
        if "charset=" in content_type:
            try:
                charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip().strip('"')
            except Exception:
                charset = "utf-8"

        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"Response too large (exceeds {max_bytes} bytes)")

    text = data.decode(charset, errors="strict")
    return json.loads(text)

def _preview(obj, max_len=200):
    s = json.dumps(obj, ensure_ascii=False) if not isinstance(obj, str) else obj
    return s if len(s) <= max_len else s[:max_len] + "..."

if __name__ == "__main__":
    tests = []
    if len(sys.argv) > 1:
        tests.append(sys.argv[1])
    tests += [
        "https://jsonplaceholder.typicode.com/todos/1",
        "https://jsonplaceholder.typicode.com/users/1",
        "https://api.github.com/",
        "https://httpbin.org/json",
        "https://pokeapi.co/api/v2/pokemon/ditto",
    ]
    tests = tests[:5]
    for i, u in enumerate(tests, 1):
        print(f"Test {i}: {u}")
        try:
            result = fetch_and_parse_json(u)
            print(f"Parsed type: {type(result).__name__}")
            print(f"Content preview: {_preview(result)}")
        except Exception as e:
            print(f"Error: {e}")
        print("----")