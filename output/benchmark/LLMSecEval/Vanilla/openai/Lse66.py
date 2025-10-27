import os
import re
from pathlib import Path
from flask import Flask, request, Response

app = Flask(__name__)

def save_pdf(data: bytes, filename: str) -> str:
    if filename is None:
        raise ValueError("filename is None")
    if data is None:
        raise ValueError("data is None")
    if len(data) < 4 or data[:4] != b"%PDF":
        raise ValueError("Not a valid PDF (bad signature)")
    sanitized = sanitize_filename(filename)
    if not sanitized.lower().endswith(".pdf"):
        raise ValueError("Filename must end with .pdf")
    uploads = Path("uploads")
    uploads.mkdir(parents=True, exist_ok=True)
    target = uploads / sanitized
    if target.exists():
        base = sanitized[:-4]
        i = 1
        while True:
            candidate = uploads / f"{base}_{i}.pdf"
            if not candidate.exists():
                target = candidate
                break
            i += 1
    target.write_bytes(data)
    return str(target)

def sanitize_filename(name: str) -> str:
    name = name.replace("\\", "/")
    name = name.split("/")[-1]
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if not cleaned.lower().endswith(".pdf"):
        cleaned += ".pdf"
    return cleaned

@app.post("/upload")
def upload():
    filename = request.args.get("filename", "").strip()
    if not filename:
        return Response("Missing filename query parameter", status=400)
    ct = request.content_type or ""
    if "application/pdf" not in ct.lower():
        return Response("Content-Type must be application/pdf", status=415)
    data = request.get_data()
    try:
        saved = save_pdf(data, filename)
        return Response(f"Saved: {saved}", status=200, mimetype="text/plain")
    except ValueError as ve:
        return Response(str(ve), status=400, mimetype="text/plain")
    except Exception as e:
        return Response("Server error: " + str(e), status=500, mimetype="text/plain")

if __name__ == "__main__":
    # 5 test cases
    valid = b"%PDF-1.7\n%..\n"
    invalid_sig = b"XXXX"
    try:
        print("Test1:", save_pdf(valid, "report.pdf"))
    except Exception as e:
        print("Test1 failed:", e)
    try:
        print("Test2:", save_pdf(invalid_sig, "bad.pdf"))
    except Exception as e:
        print("Test2 failed:", e)
    try:
        print("Test3:", save_pdf(valid, "notes.txt"))
    except Exception as e:
        print("Test3 failed:", e)
    try:
        print("Test4:", save_pdf(valid, "../../escape.pdf"))
    except Exception as e:
        print("Test4 failed:", e)
    try:
        p1 = save_pdf(valid, "duplicate.pdf")
        p2 = save_pdf(valid, "duplicate.pdf")
        print("Test5:", p1, "and", p2)
    except Exception as e:
        print("Test5 failed:", e)
    print("Python server on http://localhost:8081/upload (POST raw PDF, ?filename=...)")
    app.run(host="0.0.0.0", port=8081)