class Response:
    def __init__(self, status: int, headers: dict, body: str):
        self.status = status
        self.headers = dict(headers)
        self.body = body

# Security: allowlists
ALLOWED_ORIGINS = {
    "https://trustedorigin.com",
    "http://localhost:3000",
}
ALLOWED_METHODS = {"GET", "POST"}
ALLOWED_HEADERS = {"content-type", "authorization", "x-requested-with"}

def _normalize_token(s: str) -> str:
    return (s or "").strip().lower()

def _is_origin_allowed(origin: str) -> bool:
    if not origin:
        return False
    return origin.strip() in ALLOWED_ORIGINS

def _parse_header_list(header_list: str) -> list:
    if not header_list:
        return []
    return [t.strip().lower() for t in header_list.split(",") if t.strip()]

def _join_csv(items) -> str:
    return ", ".join(items)

def handle_request(method: str, path: str, origin: str,
                   access_control_request_method: str = None,
                   access_control_request_headers: str = None) -> Response:
    m = (method or "").strip().upper()
    p = (path or "").strip()

    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }

    origin_allowed = _is_origin_allowed(origin)

    if m == "OPTIONS":
        if not origin_allowed:
            return Response(403, headers, "")
        req_method = (access_control_request_method or "").strip().upper()
        if req_method not in ALLOWED_METHODS:
            return Response(405, headers, "")
        requested = _parse_header_list(access_control_request_headers)
        allowed_back = []
        if requested:
            for h in requested:
                if h in ALLOWED_HEADERS:
                    allowed_back.append(h)
        else:
            allowed_back = list(ALLOWED_HEADERS)

        headers["Access-Control-Allow-Origin"] = origin.strip()
        headers["Vary"] = "Origin"
        headers["Access-Control-Allow-Methods"] = _join_csv(sorted(ALLOWED_METHODS))
        if allowed_back:
            headers["Access-Control-Allow-Headers"] = _join_csv(sorted(allowed_back))
        headers["Access-Control-Max-Age"] = "600"
        return Response(204, headers, "")

    if p != "/api/data":
        return Response(404, headers, '{"error":"not found"}')
    if m not in ALLOWED_METHODS:
        return Response(405, headers, '{"error":"method not allowed"}')

    if origin_allowed:
        headers["Access-Control-Allow-Origin"] = origin.strip()
        headers["Vary"] = "Origin"
        headers["Access-Control-Expose-Headers"] = "Content-Type, Content-Length"
    headers["Content-Type"] = "application/json; charset=utf-8"

    body = '{"message":"Hello from CORS protected API","path":"' + p + '"}'
    return Response(200, headers, body)

def _print_response(title: str, r: Response):
    print(f"== {title} ==")
    print(f"Status: {r.status}")
    for k, v in r.headers.items():
        print(f"{k}: {v}")
    print(f"Body: {r.body}\n")

def main():
    # 5 test cases
    t1 = handle_request(
        "OPTIONS", "/api/data", "https://trustedorigin.com", "GET", "Content-Type, X-Requested-With"
    )
    t2 = handle_request(
        "OPTIONS", "/api/data", "https://evil.com", "GET", "Content-Type"
    )
    t3 = handle_request(
        "GET", "/api/data", "http://localhost:3000"
    )
    t4 = handle_request(
        "OPTIONS", "/api/data", "http://localhost:3000", "DELETE", "Content-Type"
    )
    t5 = handle_request(
        "GET", "/api/data", "https://unknown.com"
    )

    _print_response("Test1 Allowed Origin Preflight", t1)
    _print_response("Test2 Disallowed Origin Preflight", t2)
    _print_response("Test3 Allowed Origin Actual GET", t3)
    _print_response("Test4 Not Allowed Method Preflight", t4)
    _print_response("Test5 Disallowed Origin Actual GET", t5)

if __name__ == "__main__":
    main()