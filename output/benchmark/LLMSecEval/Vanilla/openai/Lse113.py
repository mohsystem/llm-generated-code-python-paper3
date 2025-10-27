import subprocess
import platform

ROUTES = {}

def route(path):
    def decorator(func):
        ROUTES[path] = func
        return func
    return decorator

@route("/ping")
def ping(url):
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", url]
    else:
        cmd = ["ping", "-c", "1", url]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        pong = proc.stdout
        alive = (proc.returncode == 0)
    except Exception as e:
        pong = f"Error executing ping: {e}"
        alive = False
    return {"alive": alive, "pong": pong}

def main():
    tests = ["localhost", "127.0.0.1", "example.com", "google.com", "invalid.invalid"]
    handler = ROUTES.get("/ping")
    for t in tests:
        if handler:
            r = handler(t)
        else:
            r = ping(t)
        print(f"URL: {t}")
        print(f"Alive: {r['alive']}")
        print(f"Pong output length: {len(r['pong']) if r['pong'] is not None else 0}")
        print("----")

if __name__ == "__main__":
    main()