from typing import Dict, Tuple, Optional, List

# Configuration
ALLOWED_ORIGINS = {"https://example.com", "https://app.example.com"}
ALLOWED_METHODS = {"GET", "POST", "OPTIONS"}
ALLOWED_HEADERS = {"content-type", "x-requested-with"}
MAX_AGE_SECONDS = 600
ALLOW_CREDENTIALS = False


def _get_header(headers: Dict[str, str], key: str) -> Optional[str]:
    if headers is None or key is None:
        return None
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == key.lower():
            return v
    return None


def _is_valid_token(s: Optional[str], max_len: int) -> bool:
    if s is None:
        return False
    t = s.strip()
    if not t or len(t) > max_len:
        return False
    return True


def _sort_strings(values) -> List[str]:
    return sorted(values, key=lambda x: x.lower())


def process_request(method: str, path: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, Dict[str, str], str]:
    out_headers: Dict[str, str] = {}

    safe_method = (method or "").strip().upper()
    safe_path = (path or "").strip()

    if not _is_valid_token(safe_method, 16) or not _is_valid_token(safe_path, 128) or not safe_path.startswith("/"):
        return 400, out_headers, "Bad Request"

    origin = _get_header(headers, "Origin")
    if origin is not None:
        origin = origin.strip()
        if len(origin) > 200:
            return 400, out_headers, "Invalid Origin"

    is_preflight = safe_method == "OPTIONS" and origin is not None and _get_header(headers, "Access-Control-Request-Method") is not None

    if is_preflight:
        return _handle_preflight(headers, origin, out_headers)
    else:
        return _handle_actual(safe_method, safe_path, headers, origin, out_headers)


def _set_cors_headers(out_headers: Dict[str, str], origin: str) -> None:
    out_headers["Vary"] = "Origin"
    out_headers["Access-Control-Allow-Origin"] = origin
    if ALLOW_CREDENTIALS:
        out_headers["Access-Control-Allow-Credentials"] = "true"
    out_headers["Access-Control-Expose-Headers"] = "Content-Type"


def _handle_preflight(headers: Dict[str, str], origin: str, out_headers: Dict[str, str]) -> Tuple[int, Dict[str, str], str]:
    if origin not in ALLOWED_ORIGINS:
        return 403, out_headers, "CORS preflight failed: origin not allowed"

    req_method = _get_header(headers, "Access-Control-Request-Method")
    if not req_method:
        return 400, out_headers, "CORS preflight failed: missing ACRM"
    req_method = req_method.strip().upper()
    if req_method not in ALLOWED_METHODS:
        return 403, out_headers, "CORS preflight failed: method not allowed"

    acrh = _get_header(headers, "Access-Control-Request-Headers")
    if acrh:
        for p in [x.strip().lower() for x in acrh.split(",")]:
            if not p:
                continue
            if p not in ALLOWED_HEADERS:
                return 403, out_headers, f"CORS preflight failed: header not allowed -> {p}"

    _set_cors_headers(out_headers, origin)
    out_headers["Access-Control-Allow-Methods"] = ", ".join(_sort_strings(ALLOWED_METHODS))
    out_headers["Access-Control-Allow-Headers"] = ", ".join(_sort_strings(ALLOWED_HEADERS))
    out_headers["Access-Control-Max-Age"] = str(MAX_AGE_SECONDS)
    return 204, out_headers, ""


def _handle_actual(method: str, path: str, headers: Dict[str, str], origin: Optional[str], out_headers: Dict[str, str]) -> Tuple[int, Dict[str, str], str]:
    if origin is not None:
        if origin not in ALLOWED_ORIGINS:
            return 403, out_headers, "CORS error: origin not allowed"
        _set_cors_headers(out_headers, origin)

    if method == "GET" and path == "/data":
        out_headers["Content-Type"] = "application/json; charset=UTF-8"
        return 200, out_headers, '{"message":"ok"}'
    elif path != "/data":
        return 404, out_headers, "Not Found"
    else:
        return 405, out_headers, "Method Not Allowed"


def _headers_of(*kv: str) -> Dict[str, str]:
    m: Dict[str, str] = {}
    i = 0
    while i + 1 < len(kv):
        k = kv[i] if kv[i] is not None else ""
        v = kv[i + 1] if kv[i + 1] is not None else ""
        if len(k) <= 64 and len(v) <= 512:
            m[k] = v
        i += 2
    return m


def _print_response(label: str, resp: Tuple[int, Dict[str, str], str]) -> None:
    status, headers, body = resp
    print(label)
    print(f"Status: {status}")
    print("Headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    print(f"Body: {body}\n")


if __name__ == "__main__":
    # Test 1: Allowed origin GET
    r1 = process_request("GET", "/data", _headers_of("Origin", "https://example.com"), None)
    _print_response("Test 1:", r1)

    # Test 2: Disallowed origin
    r2 = process_request("GET", "/data", _headers_of("Origin", "https://evil.com"), None)
    _print_response("Test 2:", r2)

    # Test 3: Preflight allowed
    r3 = process_request(
        "OPTIONS",
        "/data",
        _headers_of(
            "Origin", "https://app.example.com",
            "Access-Control-Request-Method", "GET",
            "Access-Control-Request-Headers", "Content-Type, X-Requested-With"
        ),
        None
    )
    _print_response("Test 3:", r3)

    # Test 4: Preflight with disallowed header
    r4 = process_request(
        "OPTIONS",
        "/data",
        _headers_of(
            "Origin", "https://example.com",
            "Access-Control-Request-Method", "GET",
            "Access-Control-Request-Headers", "X-Secret"
        ),
        None
    )
    _print_response("Test 4:", r4)

    # Test 5: No Origin header
    r5 = process_request("GET", "/data", _headers_of("User-Agent", "TestClient/1.0"), None)
    _print_response("Test 5:", r5)