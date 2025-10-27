import os
import time

def write_secret(filename, secret):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(secret)
    try:
        os.chmod(filename, 0o400)
    except Exception:
        pass
    return os.path.basename(filename)

def main():
    for i in range(1, 6):
        fname = f"secret_py_{int(time.time() * 1000)}_{i}.txt"
        name = write_secret(fname, f"Super secret info #{i}")
        print(name)
        time.sleep(0.002)

if __name__ == "__main__":
    main()