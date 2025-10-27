from flask import Flask
import subprocess
import sys
import platform
import threading
import time

app = Flask(__name__)

def run_ping(url: str) -> str:
    flag = "-n" if platform.system().lower().startswith("win") else "-c"
    try:
        subprocess.run(["ping", flag, "1", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass
    return url

@app.route("/ping")
def ping():
    url = "example.com"
    run_ping(url)
    return url

def _run_server():
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

def main():
    # Start server in background thread so tests can run
    t = threading.Thread(target=_run_server, daemon=True)
    t.start()
    time.sleep(0.5)  # give server time to start

    # 5 test cases
    tests = ["example.com", "localhost", "127.0.0.1", "google.com", "invalid.invalid"]
    for u in tests:
        result = run_ping(u)
        print(f"Pinged and returned URL: {result}")
    # keep running briefly to allow manual testing if desired
    # Comment out the sleep to exit immediately after tests
    # time.sleep(10)

if __name__ == "__main__":
    main()