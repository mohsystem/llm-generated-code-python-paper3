from typing import Dict, Optional

def html_escape(s: Optional[str]) -> str:
    if s is None:
        return "N/A"
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#x27;")
         .replace("/", "&#x2F;")
    )

def last4_of_ssn(ssn: Optional[str]) -> str:
    if ssn is None:
        return "N/A"
    digits = "".join(ch for ch in ssn if ch.isdigit())
    if len(digits) < 4:
        return "N/A"
    return digits[-4:]

def info(session: Dict[str, str]) -> str:
    if not isinstance(session, dict):
        return http_response(400, "text/plain; charset=UTF-8", "Bad Request")
    username = html_escape(session.get("username"))
    email = html_escape(session.get("email"))
    ssn_last4 = html_escape(last4_of_ssn(session.get("ssn")))
    body = (
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Info</title></head><body>"
        "<h1>User Info</h1>"
        f"<ul><li>Username: {username}</li>"
        f"<li>Email: {email}</li>"
        f"<li>SSN Last 4: {ssn_last4}</li></ul>"
        "</body></html>"
    )
    return http_response(200, "text/html; charset=UTF-8", body)

def handle_request(method: str, path: str, session: Dict[str, str]) -> str:
    if not isinstance(method, str) or not isinstance(path, str):
        return http_response(400, "text/plain; charset=UTF-8", "Bad Request")
    if method != "GET":
        return http_response(405, "text/plain; charset=UTF-8", "Method Not Allowed")
    if path == "/info":
        return info(session)
    return http_response(404, "text/plain; charset=UTF-8", "Not Found")

def http_response(status_code: int, content_type: str, body: str) -> str:
    reasons = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed"}
    reason = reasons.get(status_code, "OK")
    body_bytes = body.encode("utf-8")
    headers = [
        f"HTTP/1.1 {status_code} {reason}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body_bytes)}",
        "Connection: close",
        "",
        ""
    ]
    return "\r\n".join(headers) + body

if __name__ == "__main__":
    # Test case 1: Valid session
    session1 = {"username": "alice", "email": "alice@example.com", "ssn": "123-45-6789"}
    print(handle_request("GET", "/info", session1))

    # Test case 2: SSN formatted with spaces and lengthy digits
    session2 = {"username": "bob", "email": "bob@example.com", "ssn": "0000 1111 2222 3333 4444 5555 6666 7777 8888 9999"}
    print(handle_request("GET", "/info", session2))

    # Test case 3: Malicious username to verify escaping
    session3 = {"username": "<img src=x onerror=alert(1)>", "email": "evil@example.com", "ssn": "111223333"}
    print(handle_request("GET", "/info", session3))

    # Test case 4: Missing SSN -> N/A
    session4 = {"username": "charlie", "email": "charlie@example.com"}
    print(handle_request("GET", "/info", session4))

    # Test case 5: Wrong path and wrong method
    session5 = {"username": "dana", "email": "dana@example.com", "ssn": "444-55-1234"}
    print(handle_request("GET", "/unknown", session5))
    print(handle_request("POST", "/info", session5))