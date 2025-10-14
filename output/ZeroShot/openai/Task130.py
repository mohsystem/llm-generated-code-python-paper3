from dataclasses import dataclass
from typing import Dict, List, Optional
import time

@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    body: str

ALLOWED_ORIGINS = {"https://example.com", "https://app.example.com"}
ALLOWED_METHODS = {"GET", "POST", "OPTIONS"}
ALLOWED_HEADERS = {"content-type", "authorization", "x-requested-with"}
EXPOSE_HEADERS = "X-Response-Time"
MAX_AGE = 600
MAX_HEADER_LIST_LEN = 1024
MAX_HEADERS = 50

def is_token(s: str) -> bool:
    if not s or len(s) > 100:
        return False
    for ch in s:
        if not (ch.isalnum() or ch == '-'):
            return False
    return True

def parse_header_list(header_list: Optional[str]) -> Optional[List[str]]:
    if header_list is None:
        return []
    s = header_list.strip()
    if len(s) > MAX_HEADER_LIST_LEN:
        return None
    parts = s.split(',')
    out: List[str] = []
    for raw in parts:
        if len(out) >= MAX_HEADERS:
            break
        t = raw.strip()
        if not t:
            continue
        if not is_token(t):
            return None
        out.append(t)
    return out

def safe_json_string(s: str) -> str:
    esc = {
        '\\': '\\\\',
        '"': '\\"',
        '\b': '\\b',
        '\f': '\\f',
        '\n': '\\n',
        '\r': '\\r',
        '\t': '\\t'
    }
    out = '"'
    for ch in s:
        if ch in esc:
            out += esc[ch]
        elif ord(ch) < 0x20:
            out += "\\u%04x" % ord(ch)
        else:
            out += ch
    out += '"'
    return out

def handle_request(method: str,
                   origin: Optional[str],
                   access_control_request_method: Optional[str],
                   access_control_request_headers: Optional[str],
                   path: str,
                   request_body: Optional[str]) -> Response:
    m = (method or "").strip().upper()
    o = (origin or "").strip()
    has_origin = bool(o)
    headers: Dict[str, str] = {}
    if m == "OPTIONS":
        headers["Vary"] = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
    else:
        headers["Vary"] = "Origin"

    origin_allowed = has_origin and o in ALLOWED_ORIGINS

    if m == "OPTIONS":
        if not origin_allowed:
            return Response(403, headers, "")
        req_method = (access_control_request_method or "").strip().upper()
        if req_method not in ALLOWED_METHODS or req_method == "OPTIONS":
            return Response(403, headers, "")
        requested_headers = parse_header_list(access_control_request_headers)
        if requested_headers is None:
            return Response(400, headers, "")
        for h in requested_headers:
            if h.lower() not in ALLOWED_HEADERS:
                return Response(403, headers, "")
        headers["Access-Control-Allow-Origin"] = o
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        headers["Access-Control-Allow-Headers"] = ", ".join(requested_headers) if requested_headers else ""
        headers["Access-Control-Max-Age"] = str(MAX_AGE)
        return Response(204, headers, "")

    if has_origin and not origin_allowed:
        return Response(403, headers, '{"error":"CORS origin denied"}')

    if path == "/api/data":
        if m == "GET":
            body = '{"message":"Hello","ts":' + str(int(time.time() * 1000)) + "}"
            headers["Content-Type"] = "application/json; charset=utf-8"
            headers["X-Response-Time"] = "1"
            headers["Cache-Control"] = "no-store"
            if origin_allowed:
                headers["Access-Control-Allow-Origin"] = o
                headers["Access-Control-Allow-Credentials"] = "true"
                headers["Access-Control-Expose-Headers"] = EXPOSE_HEADERS
            return Response(200, headers, body)
        elif m == "POST":
            safe = (request_body or "")
            if len(safe) > 1024:
                safe = safe[:1024]
            body = '{"received":' + safe_json_string(safe) + "}"
            headers["Content-Type"] = "application/json; charset=utf-8"
            headers["X-Response-Time"] = "1"
            headers["Cache-Control"] = "no-store"
            if origin_allowed:
                headers["Access-Control-Allow-Origin"] = o
                headers["Access-Control-Allow-Credentials"] = "true"
                headers["Access-Control-Expose-Headers"] = EXPOSE_HEADERS
            return Response(200, headers, body)
        else:
            return Response(405, headers, "")
    else:
        return Response(404, headers, "")

def _print_result(label: str, r: Response) -> None:
    print("=== " + label + " ===")
    print("Status:", r.status)
    for k, v in r.headers.items():
        print(f"{k}: {v}")
    if r.body:
        print("Body:", r.body)

if __name__ == "__main__":
    # 1) Preflight allowed
    r1 = handle_request("OPTIONS", "https://example.com", "GET", "Content-Type, X-Requested-With", "/api/data", None)
    _print_result("Test1 Preflight OK", r1)
    # 2) Actual GET allowed origin
    r2 = handle_request("GET", "https://app.example.com", None, None, "/api/data", None)
    _print_result("Test2 GET with CORS", r2)
    # 3) Actual POST disallowed origin
    r3 = handle_request("POST", "https://evil.com", None, None, "/api/data", '{"a":1}')
    _print_result("Test3 POST disallowed origin", r3)
    # 4) Actual GET no Origin
    r4 = handle_request("GET", None, None, None, "/api/data", None)
    _print_result("Test4 GET no origin", r4)
    # 5) Preflight bad method
    r5 = handle_request("OPTIONS", "https://example.com", "DELETE", "Authorization", "/api/data", None)
    _print_result("Test5 Preflight bad method", r5)