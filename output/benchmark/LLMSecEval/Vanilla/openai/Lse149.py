import threading
from wsgiref.simple_server import make_server, WSGIServer, WSGIRequestHandler
from urllib.parse import parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import urllib.parse
import time

MESSAGES = []

def insert_user_message_in_db(username: str, message: str) -> bool:
    if not username or not message:
        return False
    MESSAGES.append({
        "username": username.strip(),
        "message": message.strip(),
        "ts": time.time()
    })
    return True

def render_messages() -> str:
    from html import escape
    items = []
    for m in MESSAGES:
        items.append(f"<li><strong>{escape(m['username'])}:</strong> {escape(m['message'])}</li>")
    return "<ul>" + "".join(items) + "</ul>"

def render_page() -> str:
    return (
        "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Messages</title></head><body>"
        "<h1>Messages</h1>" +
        render_messages() +
        "<h2>Post a message</h2>"
        "<form method='POST' action='/post'>"
        "Username: <input name='username' required/> <br/>"
        "Message: <input name='message' required/> <br/>"
        "<button type='submit'>Post</button>"
        "</form></body></html>"
    )

def application(environ, start_response):
    path = environ.get('PATH_INFO', '/')
    method = environ.get('REQUEST_METHOD', 'GET').upper()

    if path == '/' and method == 'GET':
        body = render_page().encode('utf-8')
        start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8'),
                                  ('Content-Length', str(len(body)))])
        return [body]

    if path == '/post' and method == 'POST':
        try:
            size = int(environ.get('CONTENT_LENGTH', '0') or '0')
        except ValueError:
            size = 0
        body_bytes = environ['wsgi.input'].read(size) if size > 0 else b''
        form = parse_qs(body_bytes.decode('utf-8'))
        username = form.get('username', [''])[0]
        message = form.get('message', [''])[0]
        insert_user_message_in_db(username, message)
        start_response('302 Found', [('Location', '/')])
        return [b'']
    start_response('405 Method Not Allowed', [('Content-Type', 'text/plain; charset=utf-8')])
    return [b'Method Not Allowed']

def start_server(port: int):
    httpd = make_server('', port, application)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd

def http_post_form(url: str, data: dict) -> int:
    encoded = urllib.parse.urlencode(data).encode('utf-8')
    req = Request(url, data=encoded, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urlopen(req) as resp:
            return resp.getcode()
    except HTTPError as e:
        return e.code
    except URLError:
        return 0

def http_get(url: str) -> str:
    with urlopen(url) as resp:
        return resp.read().decode('utf-8')

if __name__ == '__main__':
    port = 8001
    server = start_server(port)
    time.sleep(0.2)

    # 5 test cases
    for i in range(1, 6):
        code = http_post_form(f'http://localhost:{port}/post', {'username': f'user{i}', 'message': f'hello world {i}'})
        print(f'POST {i} response: {code}')

    page = http_get(f'http://localhost:{port}/')
    print(page)

    server.shutdown()