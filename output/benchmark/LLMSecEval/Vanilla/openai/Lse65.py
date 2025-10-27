import os
import sys
import time
import urllib.request
import urllib.error

def upload_pdf(file_path, url):
    if not os.path.isfile(file_path):
        return (-1, f"File not found: {file_path}")

    boundary = "----LSE65Boundary" + str(int(time.time() * 1000))
    crlf = "\r\n"

    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        filename = os.path.basename(file_path)

        # Build multipart body
        parts = []
        parts.append(f"--{boundary}{crlf}".encode("utf-8"))
        parts.append(f"Content-Disposition: form-data; name=\"destination\"{crlf}{crlf}".encode("utf-8"))
        parts.append(f"uploads{crlf}".encode("utf-8"))

        parts.append(f"--{boundary}{crlf}".encode("utf-8"))
        parts.append(f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"{crlf}".encode("utf-8"))
        parts.append(f"Content-Type: application/pdf{crlf}{crlf}".encode("utf-8"))
        parts.append(file_bytes)
        parts.append(f"{crlf}--{boundary}--{crlf}".encode("utf-8"))

        body = b"".join(parts)

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "Connection": "close",
        }

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.getcode()
            data = resp.read()
            try:
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                text = ""
            return (status, text)
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            err_body = str(e)
        return (e.code if hasattr(e, "code") else -1, err_body)
    except Exception as ex:
        return (-1, str(ex))

if __name__ == "__main__":
    url = "http://127.0.0.1:8080/upload"
    test_files = [
        "./sample1.pdf",
        "./sample2.pdf",
        "./docs/test.pdf",
        "./data/report.pdf",
        "./dummy.pdf"
    ]
    for fp in test_files:
        status, resp = upload_pdf(fp, url)
        print(f"Upload: {fp} -> HTTP Status: {status}")
        # Optionally print response body
        # print(resp)