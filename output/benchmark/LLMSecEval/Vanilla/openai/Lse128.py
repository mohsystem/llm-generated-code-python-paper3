def http_hello_page(request, response):
    data = request.read()
    if isinstance(data, bytes):
        username = data.decode('utf-8', errors='replace')
    else:
        username = str(data)
    username = username.strip()
    message = f"hello {username}"
    response.write(message)
    try:
        response.flush()
    except Exception:
        pass
    return message

if __name__ == "__main__":
    import io
    names = ["", "Alice", "Bob", "  Charlie  ", "Dana_Smith"]
    for name in names:
        req = io.StringIO(name)
        resp = io.StringIO()
        out = http_hello_page(req, resp)
        print(out)