import sys
import json
from urllib.request import urlopen, Request

def fetch_json_from_url(url: str):
    req = Request(url, headers={"Accept": "application/json", "User-Agent": "Python-urllib"})
    with urlopen(req, timeout=15) as resp:
        data = resp.read()
    text = data.decode("utf-8", errors="replace")
    return json.loads(text)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        obj = fetch_json_from_url(sys.argv[1])
        print(json.dumps(obj, ensure_ascii=False))
    else:
        tests = [
            "https://jsonplaceholder.typicode.com/todos/1",
            "https://jsonplaceholder.typicode.com/posts/1",
            "https://jsonplaceholder.typicode.com/users/1",
            "https://jsonplaceholder.typicode.com/comments/1",
            "https://jsonplaceholder.typicode.com/albums/1",
        ]
        for u in tests:
            print("URL:", u)
            obj = fetch_json_from_url(u)
            print(json.dumps(obj, ensure_ascii=False))
            print()