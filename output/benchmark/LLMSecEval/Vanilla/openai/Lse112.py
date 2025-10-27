from flask import Flask, request
import subprocess
import sys
import platform

app = Flask(__name__)

def ping(url: str) -> str:
    try:
        is_win = platform.system().lower().startswith('win')
        cmd = ["ping", "-n", "1", url] if is_win else ["ping", "-c", "1", url]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True)
    except Exception:
        pass
    return url

@app.route("/ping", methods=["GET"])
def ping_route():
    url = request.args.get("url", default="example.com")
    return ping(url)

if __name__ == "__main__":
    tests = ["localhost", "example.com", "127.0.0.1", "8.8.8.8", "github.com"]
    for t in tests:
        print("Returned URL:", ping(t))
    # Start the server after tests
    app.run(host="0.0.0.0", port=5000)