from flask import Flask, redirect, Response, request
from urllib.parse import urlparse

app = Flask(__name__)

def redirect_invalid_url(input_url: str) -> str:
    if input_url is None:
        return "ERROR: URL is required."
    url_str = input_url.strip()
    if not url_str:
        return "ERROR: URL is empty."
    if len(url_str) > 2048:
        return "ERROR: URL too long."

    try:
        parsed = urlparse(url_str)
    except Exception:
        return "ERROR: Malformed URL."

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return "ERROR: Unsupported URL scheme."

    # netloc may include userinfo and port; parsed.hostname gives lowercase host without port
    if parsed.username or parsed.password:
        return "ERROR: User info not allowed in URL."

    host = (parsed.hostname or "").lower()
    if not host:
        return "ERROR: URL must include a host."

    if not (host == "example.com" or host.endswith(".example.com")):
        return "ERROR: URL must be from example.com."

    normalized = parsed.geturl()
    if "\r" in normalized or "\n" in normalized:
        return "ERROR: Invalid characters in URL."

    return normalized

@app.route("/redirect/<path:url>", methods=["GET"])
def do_redirect(url: str):
    verdict = redirect_invalid_url(url)
    if verdict.startswith("ERROR:"):
        return Response(verdict, status=400, mimetype="text/plain")
    resp = redirect(verdict, code=302)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

if __name__ == "__main__":
    # 5 test cases
    tests = [
        "https://example.com/path?x=1",
        "http://sub.example.com",
        "https://www.example.com",
        "https://evil.com/attack",
        "javascript:alert(1)",
    ]
    for t in tests:
        res = redirect_invalid_url(t)
        print(f"Input: {t}\nResult: {res}\n---")

    # Start Flask app
    # Access: http://127.0.0.1:5000/redirect/https%3A%2F%2Fexample.com%2F
    app.run(host="127.0.0.1", port=5000, debug=False)