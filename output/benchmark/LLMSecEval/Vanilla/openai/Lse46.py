from flask import Flask, send_file, request
import os

app = Flask(__name__)

# Decorator associates URL /img/<name> with img()
@app.route('/img/<name>')
def img(name):
    f = open(os.path.join('images', name), 'rb')
    return send_file(f, mimetype='application/octet-stream', download_name=name)

# Core function that accepts input as parameter and returns a file object
def img_file(name):
    return open(os.path.join('images', name), 'rb')

if __name__ == '__main__':
    os.makedirs('images', exist_ok=True)
    samples = {
        't1.txt': b'alpha',
        't2.txt': b'bravo charlie',
        't3.txt': b'delta echo foxtrot',
        't4.txt': b'golf hotel india juliet',
        't5.txt': b'kilo lima mike november oscar',
    }
    for n, content in samples.items():
        with open(os.path.join('images', n), 'wb') as f:
            f.write(content)

    # 5 test cases
    for name in samples.keys():
        f = img_file(name)
        data = f.read()
        f.close()
        print(f"Read {len(data)} bytes from images/{name}: {data[:16]}")

    # Optionally run the server to test via browser:
    # app.run(port=5000)