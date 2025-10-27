#!/usr/bin/env python3
import html
import re
import socketserver
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote
from typing import Tuple


def html_escape(s: str) -> str:
    return html.escape(s or "", quote=True)


def is_valid_username(username: str) -> bool:
    if username is None:
        return False
    if not (1 <= len(username) <= 64):
        return False
    return re.fullmatch(r"[A-Za-z0-9._-]+", username) is not None


def is_valid_email(email: str) -> bool:
    if email is None:
        return False
    if not (5 <= len(email) <= 254):
        return False
    # Basic robust email check (no fancy rules)
    if email.count("@") != 1:
        return False
    local, domain = email.split("@", 1)
    if not local or not domain:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    if "." not in domain:
        return False
    if not re.fullmatch(r"[A-Za-z0-9._%+\-]+", local):
        return False
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", domain):
        return False
    return True


def extract_last4(ssn_raw: str) -> str | None:
    if ssn_raw is None:
        return None
    digits = "".join([c for c in ssn_raw if c.isdigit()])
    if len(digits) < 4:
        return None
    return digits[-4:]


def generate_info_page(username: str, email: str, ssn: str) -> str:
    if not is_valid_username(username):
        raise ValueError("Invalid username")
    if not is_valid_email(email):
        raise ValueError("Invalid email")
    last4 = extract_last4(ssn)
    if last4 is None:
        raise ValueError("Invalid SSN")
    safe_user = html_escape(username)
    safe_email = html_escape(email)
    safe_last4 = html_escape(last4)
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>User Info</title></head>"
        "<body><h1>User Info</h1><ul>"
        f"<li>Username: {safe_user}</li>"
        f"<li>Email: {safe_email}</li>"
        f"<li>SSN (last 4): {safe_last4}</li>"
        "</ul></body></html>"
    )


def validate_and_render(username: str | None, email: str | None, ssn: str | None) -> Tuple[int, str, str]:
    # returns (status_code, content_type, body)
    if username is None or email is None or ssn is None:
        return 400, "text/plain; charset=UTF-8", "Missing parameters"
    try:
        body = generate_info_page(username, email, ssn)
        return 200, "text/html; charset=UTF-8", body
    except ValueError:
        return 400, "text/plain; charset=UTF-8", "Invalid input"


class InfoHandler(BaseHTTPRequestHandler):
    server_version = "SecureSimpleHTTP/1.0"

    def log_message(self, format: str, *args) -> None:
        # Suppress default logging to avoid accidental PII logs
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/info":
            self._send_response(404, "text/plain; charset=UTF-8", "Not Found")
            return
        qs = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=False)
        username = qs.get("username", [None])[0]
        email = qs.get("email", [None])[0]
        ssn = qs.get("ssn", [None])[0]
        if username is not None:
            username = unquote(username)
        if email is not None:
            email = unquote(email)
        if ssn is not None:
            ssn = unquote(ssn)
        status, ctype, body = validate_and_render(username, email, ssn)
        self._send_response(status, ctype, body)

    def _send_response(self, code: int, content_type: str, body: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def run_server(port: int = 8080):
    with HTTPServer(("127.0.0.1", port), InfoHandler) as httpd:
        # Avoid verbose logging; serve forever
        httpd.serve_forever()


def _run_tests():
    tests = [
        ("alice_01", "alice@example.com", "123-45-6789", True),
        ("bob", "bob@example.org", "0000", True),
        ("charlie.z", "charlie.z@example.co.uk", "111223333", True),
        ("bad user", "x@example.com", "111-22-3333", False),
        ("dana", "invalid-email", "9999", False),
    ]
    passed = 0
    for u, e, s, should_pass in tests:
        try:
            page = generate_info_page(u, e, s)
            ok = "<script" not in page.lower() and (extract_last4(s) in page)
            if should_pass and ok:
                passed += 1
            if not should_pass:
                # if it shouldn't pass, but no exception, mark failure
                pass
        except Exception:
            if not should_pass:
                passed += 1
    # print(f"Tests passed: {passed}/5")


if __name__ == "__main__":
    _run_tests()
    run_server(8080)