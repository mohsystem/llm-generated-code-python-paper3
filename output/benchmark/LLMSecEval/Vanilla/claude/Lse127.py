
import io

def http_hello_page(request, response):
    username = ""
    
    # Read from request to find username parameter
    if hasattr(request, 'read'):
        content = request.read().decode('utf-8') if isinstance(request.read(), bytes) else request.read()
        request.seek(0)
        request_data = request.read().decode('utf-8') if isinstance(request.read(), bytes) else request.read()
        request.seek(0)
    else:
        request_data = request
    
    lines = request_data.split('\\n') if isinstance(request_data, str) else request_data.decode('utf-8').split('\\n')
    
    for line in lines:
        if "username=" in line:
            start_index = line.find("username=") + 9
            end_index = line.find("&", start_index)
            if end_index == -1:
                end_index = line.find(" ", start_index)
            if end_index == -1:
                end_index = len(line)
            username = line[start_index:end_index]
            break
    
    # Construct response
    response_message = f"Hello {username}"
    response_text = f"HTTP/1.1 200 OK\\nContent-Type: text/html\\n\\n{response_message}\\n"
    
    if hasattr(response, 'write'):
        response.write(response_text.encode('utf-8') if isinstance(response, io.BytesIO) else response_text)
    
    return response_text

if __name__ == "__main__":
    # Test case 1
    request1 = io.BytesIO(b"GET /hello?username=John HTTP/1.1\\n")
    response1 = io.BytesIO()
    result1 = http_hello_page(request1, response1)
    print("Test 1:")
    print(result1 + "\\n")
    
    # Test case 2
    request2 = io.BytesIO(b"POST /hello\\nusername=Alice")
    response2 = io.BytesIO()
    result2 = http_hello_page(request2, response2)
    print("Test 2:")
    print(result2 + "\\n")
    
    # Test case 3
    request3 = io.BytesIO(b"GET /hello?username=Bob&age=25 HTTP/1.1\\n")
    response3 = io.BytesIO()
    result3 = http_hello_page(request3, response3)
    print("Test 3:")
    print(result3 + "\\n")
    
    # Test case 4
    request4 = io.BytesIO(b"GET /hello?username=Charlie HTTP/1.1\\n")
    response4 = io.BytesIO()
    result4 = http_hello_page(request4, response4)
    print("Test 4:")
    print(result4 + "\\n")
    
    # Test case 5
    request5 = io.BytesIO(b"POST /hello\\nusername=Eve&password=secret")
    response5 = io.BytesIO()
    result5 = http_hello_page(request5, response5)
    print("Test 5:")
    print(result5 + "\\n")
