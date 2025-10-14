import secrets
from typing import Dict, Optional

# Simple in-memory session and CSRF-protected settings update simulation
_sessions: Dict[str, Dict[str, str]] = {}

def _new_token(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)

def _parse_sid_from_cookie(cookie: Optional[str]) -> Optional[str]:
    if not cookie:
        return None
    for part in cookie.split(";"):
        p = part.strip()
        if p.startswith("SID="):
            return p[4:].strip()
    return None

def _get_or_create_session(sid: Optional[str]) -> Dict[str, str]:
    global _sessions
    if sid and sid in _sessions:
        return _sessions[sid]
    new_sid = _new_token(16)
    _sessions[new_sid] = {
        "sid": new_sid,
        "csrf": "",
        "username": "default_user",
        "email": "user@example.com",
    }
    return _sessions[new_sid]

def process_request(method: str, path: str, headers: Optional[Dict[str, str]], form: Optional[Dict[str, str]]) -> str:
    try:
        if path != "/settings":
            return "HTTP/1.1 404 Not Found\nContent-Type: text/plain; charset=utf-8\n\nNot Found"
        cookie = (headers or {}).get("Cookie")
        sid = _parse_sid_from_cookie(cookie)
        session = _get_or_create_session(sid)

        if method.upper() == "GET":
            session["csrf"] = _new_token(16)
            body = (
                "<!doctype html><html><head><title>Settings</title></head><body>"
                "<h1>User Settings</h1>"
                "<form method=\"POST\" action=\"/settings\">"
                f"<input type=\"hidden\" name=\"csrf_token\" value=\"{session['csrf']}\"/>"
                f"<label>Username: <input type=\"text\" name=\"username\" value=\"{session['username']}\"/></label><br/>"
                f"<label>Email: <input type=\"email\" name=\"email\" value=\"{session['email']}\"/></label><br/>"
                "<button type=\"submit\">Update</button>"
                "</form>"
                "</body></html>"
            )
            return (
                "HTTP/1.1 200 OK\n"
                f"Set-Cookie: SID={session['sid']}; HttpOnly; SameSite=Strict\n"
                "Content-Type: text/html; charset=utf-8\n\n"
                + body
            )
        elif method.upper() == "POST":
            token = (form or {}).get("csrf_token", "")
            if token == session.get("csrf"):
                if form:
                    session["username"] = form.get("username", session["username"])
                    session["email"] = form.get("email", session["email"])
                session["csrf"] = _new_token(16)
                body = f"Settings updated successfully for {session['username']} ({session['email']})"
                return (
                    "HTTP/1.1 200 OK\n"
                    f"Set-Cookie: SID={session['sid']}; HttpOnly; SameSite=Strict\n"
                    "Content-Type: text/plain; charset=utf-8\n\n"
                    + body
                )
            else:
                return (
                    "HTTP/1.1 403 Forbidden\n"
                    f"Set-Cookie: SID={session['sid']}; HttpOnly; SameSite=Strict\n"
                    "Content-Type: text/plain; charset=utf-8\n\n"
                    "Forbidden: invalid CSRF token"
                )
        else:
            return "HTTP/1.1 405 Method Not Allowed\nAllow: GET, POST\nContent-Type: text/plain; charset=utf-8\n\nMethod Not Allowed"
    except Exception:
        return "HTTP/1.1 500 Internal Server Error\nContent-Type: text/plain; charset=utf-8\n\nInternal Server Error"

def _extract_set_cookie_sid(response: str) -> Optional[str]:
    marker = "Set-Cookie: SID="
    i = response.find(marker)
    if i < 0:
        return None
    start = i + len(marker)
    end = response.find("\n", start)
    line = response[start:end] if end >= 0 else response[start:]
    semi = line.find(";")
    if semi >= 0:
        line = line[:semi]
    return line.strip()

def _extract_csrf_token(response: str) -> Optional[str]:
    name = "name=\"csrf_token\""
    i = response.find(name)
    if i < 0:
        return None
    vm = "value=\""
    v = response.find(vm, i)
    if v < 0:
        return None
    start = v + len(vm)
    end = response.find("\"", start)
    if end < 0:
        return None
    return response[start:end]

if __name__ == "__main__":
    # Test 1: GET
    resp1 = process_request("GET", "/settings", {}, None)
    print("=== Test 1: GET /settings (no cookie) ===")
    print(resp1)

    sid = _extract_set_cookie_sid(resp1)
    csrf1 = _extract_csrf_token(resp1)
    headers = {"Cookie": f"SID={sid}"}

    # Test 2: POST with valid CSRF
    resp2 = process_request("POST", "/settings", headers, {"csrf_token": csrf1, "username": "alice", "email": "alice@example.com"})
    print("=== Test 2: POST /settings (valid CSRF) ===")
    print(resp2)

    # Test 3: POST missing CSRF
    resp3 = process_request("POST", "/settings", headers, {"username": "mallory", "email": "mallory@example.com"})
    print("=== Test 3: POST /settings (missing CSRF) ===")
    print(resp3)

    # Test 4: POST invalid CSRF
    resp4 = process_request("POST", "/settings", headers, {"csrf_token": "badtoken", "username": "bob", "email": "bob@example.com"})
    print("=== Test 4: POST /settings (invalid CSRF) ===")
    print(resp4)

    # Test 5: GET new token then POST with valid token
    resp5a = process_request("GET", "/settings", headers, None)
    csrf_new = _extract_csrf_token(resp5a)
    resp5 = process_request("POST", "/settings", headers, {"csrf_token": csrf_new, "username": "charlie", "email": "charlie@example.com"})
    print("=== Test 5: POST /settings after fresh GET (valid CSRF) ===")
    print(resp5)