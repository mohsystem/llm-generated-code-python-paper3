from flask import Flask, request, Response
import os
import random

app = Flask(__name__)

def img(file_path: str) -> bytes:
    with open(file_path, "rb") as f:
        return f.read()

@app.route("/img", methods=["GET"])
def img_route():
    file_param = request.args.get("file")
    if not file_param:
        return Response("Missing 'file' parameter", status=400)
    try:
        data = img(file_param)
        return Response(data, mimetype="application/octet-stream", status=200)
    except FileNotFoundError:
        return Response("File not found", status=404)
    except Exception as e:
        return Response(f"Server error: {e}", status=500)

if __name__ == "__main__":
    # Create 5 test files
    files = ["py_test1.bin", "py_test2.bin", "py_test3.bin", "py_test4.bin", "py_test5.bin"]

    with open(files[0], "wb") as f:
        f.write(b"Hello Python")
    with open(files[1], "wb") as f:
        f.write(bytes([0, 1, 2, 255, 16]))
    with open(files[2], "wb") as f:
        f.write(("abc" * 10).encode("utf-8"))
    with open(files[3], "wb") as f:
        f.write(b"")
    with open(files[4], "wb") as f:
        random.seed(42)
        f.write(bytes([random.randrange(0, 256) for _ in range(1024)]))

    # 5 test cases calling img()
    for fp in files:
        data = img(fp)
        preview = list(data[:8])
        print(f"Read {fp} -> length={len(data)}" + (f", first8={preview}" if len(preview) else ""))

    # Start Flask server
    app.run(host="0.0.0.0", port=5000, debug=False)