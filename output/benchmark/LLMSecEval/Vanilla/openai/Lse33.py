from urllib.parse import urlparse
from flask import Flask, request, redirect, Response

app = Flask(__name__)

def redirect_invalid_url(url: str):
    if not url or not isinstance(url, str):
        return (False, "Missing url parameter")
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return (False, "Unsupported scheme")
        if not parsed.netloc:
            return (False, "Invalid URL")
        host = parsed.hostname or ""
        if host.lower() == "example.com":
            return (True, url)
        else:
            return (False, "Invalid domain")
    except Exception:
        return (False, "Invalid URL")

@app.route("/go")
def go():
    url = request.args.get("url", "")
    ok, val = redirect_invalid_url(url)
    if ok:
        return redirect(val, code=302)
    else:
        return Response(val, status=400, mimetype="text/plain")

if __name__ == "__main__":
    # 5 test cases
    tests = [
        "https://example.com/path",
        "http://example.com",
        "https://sub.example.com",
        "https://example.org",
        "not a url",
    ]
    for t in tests:
        ok, val = redirect_invalid_url(t)
        print(f"Test: {t} -> ok={ok} result={val}")
    # Start server
    app.run(host="127.0.0.1", port=5000)