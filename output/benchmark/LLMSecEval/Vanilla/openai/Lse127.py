import io

def http_hello_page(request, response):
    data = request.read()
    if isinstance(data, bytes):
        data = data.decode('utf-8', errors='replace')
    username = data.strip()
    message = f"Hello {username}"
    response.write(message)
    return message

if __name__ == "__main__":
    test_usernames = ["Alice", "Bob", "Charlie", "", "Eve Adams"]
    for name in test_usernames:
        req = io.StringIO(name)
        resp = io.StringIO()
        result = http_hello_page(req, resp)
        print("Returned:", result)
        print("Response Stream:", resp.getvalue())