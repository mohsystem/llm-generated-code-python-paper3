import io

def http_hello_page(request_stream, response_stream):
    data = request_stream.read()
    if isinstance(data, bytes):
        text = data.decode('utf-8', errors='replace')
    else:
        text = str(data)
    username = text.strip()
    out = f"Hello {username}"
    try:
        response_stream.write(out.encode('utf-8'))
    except TypeError:
        response_stream.write(out)
    return out

if __name__ == "__main__":
    tests = ["Alice", "  Bob  ", "", "Bob123", "世界"]
    for i, t in enumerate(tests, 1):
        req = io.BytesIO(t.encode('utf-8'))
        res = io.BytesIO()
        ret = http_hello_page(req, res)
        written = res.getvalue().decode('utf-8')
        print(f"Test {i}: return={ret}, response={written}")