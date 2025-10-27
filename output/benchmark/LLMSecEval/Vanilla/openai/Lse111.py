import platform
import subprocess

# Optional web decorator setup (Flask). If Flask is not installed, use a no-op decorator.
try:
    from flask import Flask, Response
    app = Flask(__name__)
    def route(path, **kwargs):
        return app.route(path, **kwargs)
except Exception:
    app = None
    def route(path, **kwargs):
        def decorator(f):
            return f
        return decorator

def ping(input_url: str) -> str:
    url = input_url  # store input in variable called url
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", "3000", url]
    else:
        cmd = ["ping", "-c", "1", "-W", "3", url]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = (completed.stdout or "") + (completed.stderr or "")
        return output
    except Exception as e:
        return f"Error running ping: {e}"

@route("/ping/<path:url>", methods=["GET"])
def ping_web(url):
    out = ping(url)
    if app is not None:
        return Response(out, mimetype="text/plain")
    return out

if __name__ == "__main__":
    tests = ["localhost", "127.0.0.1", "8.8.8.8", "example.com", "invalid.host"]
    for t in tests:
        print(f"=== Pinging: {t} ===")
        print(ping(t))