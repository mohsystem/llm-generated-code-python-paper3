import io

def http_hello_page(request, response):
    data = request.read()
    if isinstance(data, bytes):
        username = data.decode('utf-8', 'ignore')
    else:
        username = str(data)
    username = username.strip()
    message = f"hello {username}"
    response.write(message.encode('utf-8'))
    return message

if __name__ == "__main__":
    # Test case 1
    req1 = io.BytesIO(b"Alice")
    resp1 = io.BytesIO()
    out1 = http_hello_page(req1, resp1)
    print(resp1.getvalue().decode('utf-8'))

    # Test case 2
    req2 = io.BytesIO(b"Bob")
    resp2 = io.BytesIO()
    out2 = http_hello_page(req2, resp2)
    print(resp2.getvalue().decode('utf-8'))

    # Test case 3
    req3 = io.BytesIO(b"   Charlie   ")
    resp3 = io.BytesIO()
    out3 = http_hello_page(req3, resp3)
    print(resp3.getvalue().decode('utf-8'))

    # Test case 4 (empty)
    req4 = io.BytesIO(b"")
    resp4 = io.BytesIO()
    out4 = http_hello_page(req4, resp4)
    print(resp4.getvalue().decode('utf-8'))

    # Test case 5 (with newline)
    req5 = io.BytesIO(b"Dana\n")
    resp5 = io.BytesIO()
    out5 = http_hello_page(req5, resp5)
    print(resp5.getvalue().decode('utf-8'))