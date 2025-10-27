from flask import Flask, session, make_response, request

app = Flask(__name__)
app.secret_key = "replace-with-a-secure-random-secret"

def info(sess: dict) -> str:
    username = sess.get("username", "guest")
    email = sess.get("email", "guest@example.com")
    ssn = sess.get("ssn", "")
    digits = "".join(ch for ch in ssn if ch.isdigit())
    last4 = digits[-4:] if len(digits) > 0 else "N/A"
    html = []
    html.append("<!DOCTYPE html><html><head><title>Info</title></head><body>")
    html.append("<h1>User Info</h1>")
    html.append(f"<p>Username: {escape_html(username)}</p>")
    html.append(f"<p>Email: {escape_html(email)}</p>")
    html.append(f"<p>SSN (last 4): {escape_html(last4)}</p>")
    html.append("</body></html>")
    return "".join(html)

def escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#39;")
    )

@app.get("/info")
def info_route():
    # Ensure session has the required keys; in a real app these would be set upon login or similar
    session.setdefault("username", "guest")
    session.setdefault("email", "guest@example.com")
    session.setdefault("ssn", "0000")
    html = info(dict(session))
    resp = make_response(html, 200)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

if __name__ == "__main__":
    # 5 test cases using the info() function directly
    tests = [
        {"username": "alice", "email": "alice@example.com", "ssn": "123-45-6789"},
        {"username": "bob", "email": "bob@x.com", "ssn": "0000"},
        {"username": "carol", "email": "carol@x.com", "ssn": "987654321"},
        {"username": "dave", "email": "dave@x.com", "ssn": ""},
        {"username": "eve", "email": "eve@x.com", "ssn": "12-34"},
    ]
    for i, t in enumerate(tests, 1):
        print(f"TEST {i} OUTPUT:")
        print(info(t))
        print("-----")
    # To run the server, uncomment the following line:
    # app.run(host="127.0.0.1", port=5000, debug=False)