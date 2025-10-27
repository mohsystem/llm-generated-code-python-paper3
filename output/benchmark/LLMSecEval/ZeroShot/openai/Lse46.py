from flask import Flask, request, Response
import os
import re
import mimetypes

app = Flask(__name__)

ALLOWED = re.compile(r'^[A-Za-z0-9._-]{1,255}$')
BASE_DIR = os.path.realpath(os.path.join(os.getcwd(), 'images'))

def _guess_mime(path):
    mime, _ = mimetypes.guess_type(path)
    if mime:
        return mime
    # Fallbacks
    name = os.path.basename(path).lower()
    if name.endswith('.svg'):
        return 'image/svg+xml'
    if name.endswith('.webp'):
        return 'image/webp'
    if name.endswith('.txt'):
        return 'text/plain; charset=utf-8'
    return 'application/octet-stream'

def serve_image_by_name(name: str):
    # Validate parameter
    if not name:
        return Response("Missing 'name' parameter", status=400, mimetype='text/plain; charset=utf-8')
    if not ALLOWED.fullmatch(name) or name.startswith('.'):
        return Response("Invalid file name", status=400, mimetype='text/plain; charset=utf-8')

    # Ensure base dir exists
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
    except OSError:
        return Response("Internal Server Error", status=500, mimetype='text/plain; charset=utf-8')

    candidate = os.path.realpath(os.path.join(BASE_DIR, name))

    # Prevent path traversal
    if not candidate.startswith(BASE_DIR + os.sep):
        return Response("Invalid path", status=400, mimetype='text/plain; charset=utf-8')

    # Check existence and deny symlinks
    if not os.path.exists(candidate) or os.path.isdir(candidate):
        return Response("Not found", status=404, mimetype='text/plain; charset=utf-8')
    if os.path.islink(candidate):
        return Response("Forbidden", status=403, mimetype='text/plain; charset=utf-8')

    try:
        with open(candidate, 'rb') as f:
            data = f.read()
        return Response(data, status=200, mimetype=_guess_mime(candidate))
    except PermissionError:
        return Response("Forbidden", status=403, mimetype='text/plain; charset=utf-8')
    except OSError:
        return Response("Internal Server Error", status=500, mimetype='text/plain; charset=utf-8')

@app.get('/img')
def img():
    name = request.args.get('name', '')
    return serve_image_by_name(name)

if __name__ == '__main__':
    # Prepare test environment
    os.makedirs(BASE_DIR, exist_ok=True)
    sample = os.path.join(BASE_DIR, 'hello.txt')
    if not os.path.exists(sample):
        with open(sample, 'wb') as f:
            f.write(b'Hello world')

    # 5 test cases using Flask test client (no server needed)
    with app.test_client() as client:
        cases = [
            '/img?name=hello.txt',   # 200
            '/img?name=',            # 400
            '/img?name=../secret',   # 400
            '/img?name=bad/name',    # 400
            '/img?name=nope.png'     # 404
        ]
        for url in cases:
            resp = client.get(url)
            print(f"{url} -> status={resp.status_code}, type={resp.headers.get('Content-Type')}, bytes={len(resp.data)}")