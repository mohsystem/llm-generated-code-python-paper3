import platform
import subprocess

# ping() takes a URL, stores it in variable called 'url', runs ping, returns output
def ping(input_url: str) -> str:
    url = input_url  # store input into 'url' variable as specified
    is_windows = platform.system().lower().startswith("win")
    flag = "-n" if is_windows else "-c"
    try:
        result = subprocess.run(
            ["ping", flag, "4", url],
            capture_output=True,
            text=True
        )
        return result.stdout if result.stdout else result.stderr
    except Exception as e:
        return f"Error running ping: {e}"

def main():
    tests = [
        "127.0.0.1",
        "localhost",
        "example.com",
        "google.com",
        "invalid.invalid"
    ]
    for i, t in enumerate(tests, 1):
        print(f"=== Python Test {i} -> {t} ===")
        print(ping(t))

if __name__ == "__main__":
    main()