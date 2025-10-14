from typing import Dict, Optional, Tuple

ALLOWED_ORIGINS = {"https://example.com", "https://app.local"}
ALLOWED_METHODS = {"GET", "POST"}
ALLOWED_HEADERS_DEFAULT = "Content-Type, Authorization, X-Requested-With"

class Response:
    def __init__(self, status: int, headers: Dict[str, str], body: str):
        self.status = status
        self.headers = headers
        self.body = body

def _get_header(headers: Dict[str, str], key: str) -> Optional[str]:
    if headers is None:
        return None
    for k, v in headers.items():
        if k.lower() == key.lower():
            return v
    return None

def _origin_allowed(origin: Optional[str]) -> bool:
    return origin is not None and origin in ALLOWED_ORIGINS

def handle_request(method: str, origin: Optional[str], path: str, request_headers: Dict[str, str]) -> Response:
    method = (method or "").upper()
    headers_out: Dict[str, str] = {}

    if method == "OPTIONS":
        if not _origin_allowed(origin):
            return Response(403, headers_out, "Forbidden: Origin not allowed")
        req_method = _get_header(request_headers, "Access-Control-Request-Method")
        if not req_method:
            return Response(400, headers_out, "Bad Request: Missing Access-Control-Request-Method")
        req_method = req_method.upper()
        if req_method not in ALLOWED_METHODS:
            return Response(405, headers_out, "Method Not Allowed for CORS preflight")
        req_headers = _get_header(request_headers, "Access-Control-Request-Headers")
        headers_out["Access-Control-Allow-Origin"] = origin
        headers_out["Vary"] = "Origin"
        headers_out["Access-Control-Allow-Methods"] = ", ".join(sorted(ALLOWED_METHODS))
        headers_out["Access-Control-Allow-Headers"] = req_headers if req_headers else ALLOWED_HEADERS_DEFAULT
        headers_out["Access-Control-Max-Age"] = "600"
        return Response(204, headers_out, "")

    if path != "/hello":
        return Response(404, headers_out, "Not Found")

    if method not in ALLOWED_METHODS:
        return Response(405, headers_out, "Method Not Allowed")

    if origin is not None:
        if not _origin_allowed(origin):
            return Response(403, headers_out, "Forbidden: Origin not allowed")
        headers_out["Access-Control-Allow-Origin"] = origin
        headers_out["Vary"] = "Origin"
        headers_out["Access-Control-Expose-Headers"] = "X-RateLimit-Remaining"

    headers_out["Content-Type"] = "application/json"
    headers_out["X-RateLimit-Remaining"] = "42"
    body = f'{{"message":"Hello from CORS-enabled API","method":"{method}"}}'
    return Response(200, headers_out, body)

if __name__ == "__main__":
    tests = [
        {"METHOD": "GET", "ORIGIN": "https://example.com", "PATH": "/hello"},
        {"METHOD": "OPTIONS", "ORIGIN": "https://example.com", "PATH": "/hello",
         "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Content-Type, X-Test"},
        {"METHOD": "GET", "ORIGIN": "https://evil.com", "PATH": "/hello"},
        {"METHOD": "POST", "ORIGIN": "https://app.local", "PATH": "/hello"},
        {"METHOD": "OPTIONS", "ORIGIN": "https://example.com", "PATH": "/hello",
         "Access-Control-Request-Method": "PUT"},
    ]
    for i, t in enumerate(tests, 1):
        method = t.get("METHOD", "GET")
        origin = t.get("ORIGIN")
        path = t.get("PATH", "/hello")
        req_headers = {k: v for k, v in t.items() if k not in ("METHOD", "ORIGIN", "PATH")}
        r = handle_request(method, origin, path, req_headers)
        print(f"=== Python Test {i} ===")
        print(f"Status: {r.status}")
        for k, v in r.headers.items():
            print(f"{k}: {v}")
        print(f"Body: {r.body}")