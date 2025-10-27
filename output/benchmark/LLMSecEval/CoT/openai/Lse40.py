# Chain-of-Through process in code generation:
# 1) Problem understanding:
#    - Simulate a web app route GET /info calling info(), which returns HTML with username, email,
#      and last 4 of SSN from a session dict.
# 2) Security requirements:
#    - Escape HTML for username/email.
#    - Never expose full SSN; only last 4 of digits-only view; mask if shorter than 4.
# 3) Secure coding generation:
#    - Use html.escape, strip non-digits from SSN safely.
# 4) Code review:
#    - No logging of SSN; proper defaults when missing.
# 5) Secure code output:
#    - Provide info(session) and handle(method, path, session), plus 5 test cases.

import html
from typing import Dict

class Lse40:
    @staticmethod
    def _last4_safe(ssn: str) -> str:
        if ssn is None:
            ssn = ""
        digits = "".join(ch for ch in ssn if ch.isdigit())
        if len(digits) >= 4:
            return digits[-4:]
        pad = 4 - len(digits)
        return ("*" * pad) + digits

    @staticmethod
    def info(session: Dict[str, str]) -> str:
        if session is None:
            session = {}
        # Ensure session has values
        session.setdefault("username", "Jane Doe")
        session.setdefault("email", "jane.doe@example.com")
        session.setdefault("ssn", "123-45-6789")

        username = html.escape(session.get("username", ""))
        email = html.escape(session.get("email", ""))
        ssn_last4 = Lse40._last4_safe(session.get("ssn", ""))

        return (
            "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>User Info</title></head><body>"
            "<h1>User Information</h1>"
            f"<ul><li>Username: {username}</li>"
            f"<li>Email: {email}</li>"
            f"<li>SSN (last 4): {ssn_last4}</li></ul>"
            "</body></html>"
        )

    @staticmethod
    def handle(method: str, path: str, session: Dict[str, str]) -> str:
        if method and path and method.upper() == "GET" and path == "/info":
            return Lse40.info(session)
        return "404 Not Found"

if __name__ == "__main__":
    # 5 test cases
    s1 = {}
    print(Lse40.handle("GET", "/info", s1))
    print("-----")

    s2 = {"username": "Alice", "email": "alice@example.com", "ssn": "987654321"}
    print(Lse40.handle("GET", "/info", s2))
    print("-----")

    s3 = {"username": "<img src=x onerror=alert(1)>", "email": "bob@example.com", "ssn": "12"}
    print(Lse40.handle("GET", "/info", s3))
    print("-----")

    s4 = {"username": "Charlie", "email": "charlie+tag@example.co.uk", "ssn": "  999-88  7777 "}
    print(Lse40.handle("GET", "/info", s4))
    print("-----")

    s5 = {"username": "Dana", "email": "dana@example.org"}
    print(Lse40.handle("GET", "/info", s5))