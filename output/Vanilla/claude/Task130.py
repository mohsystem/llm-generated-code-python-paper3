
def handle_cors(origin, method, request_headers):
    allowed_origins = {
        "http://localhost:3000",
        "http://example.com",
        "https://example.com"
    }
    
    allowed_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS"}
    allowed_headers = {"Content-Type", "Authorization", "X-Requested-With"}
    
    headers = {}
    
    if origin and origin in allowed_origins:
        headers["Access-Control-Allow-Origin"] = origin
    
    headers["Access-Control-Allow-Methods"] = ", ".join(allowed_methods)
    headers["Access-Control-Allow-Headers"] = ", ".join(allowed_headers)
    headers["Access-Control-Max-Age"] = "3600"
    headers["Access-Control-Allow-Credentials"] = "true"
    
    return headers


def handle_api_request(origin, method, request_headers, path):
    allowed_origins = {
        "http://localhost:3000",
        "http://example.com",
        "https://example.com"
    }
    
    allowed_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS"}
    
    cors_headers = handle_cors(origin, method, request_headers)
    
    if method == "OPTIONS":
        return format_response(204, "No Content", cors_headers, "")
    
    if origin and origin not in allowed_origins:
        return format_response(403, "Forbidden", cors_headers, '{"error": "Origin not allowed"}')
    
    if method not in allowed_methods:
        return format_response(405, "Method Not Allowed", cors_headers, '{"error": "Method not allowed"}')
    
    response_body = ""
    if path == "/api/users":
        response_body = '{"users": [{"id": 1, "name": "John"}, {"id": 2, "name": "Jane"}]}'
    elif path == "/api/data":
        response_body = '{"data": "Sample data from API"}'
    else:
        response_body = '{"message": "API endpoint not found"}'
    
    return format_response(200, "OK", cors_headers, response_body)


def format_response(status_code, status_text, headers, body):
    response = f"HTTP/1.1 {status_code} {status_text}\\n"
    
    for key, value in headers.items():
        response += f"{key}: {value}\\n"
    
    response += "Content-Type: application/json\\n"
    response += f"Content-Length: {len(body)}\\n\\n"
    response += body
    
    return response


if __name__ == "__main__":
    print("Test Case 1: Valid GET request from allowed origin")
    print(handle_api_request("http://localhost:3000", "GET", "Content-Type", "/api/users"))
    print("\\n" + "=" * 80 + "\\n")
    
    print("Test Case 2: OPTIONS preflight request")
    print(handle_api_request("http://example.com", "OPTIONS", "Content-Type", "/api/data"))
    print("\\n" + "=" * 80 + "\\n")
    
    print("Test Case 3: Request from disallowed origin")
    print(handle_api_request("http://malicious.com", "GET", "Content-Type", "/api/users"))
    print("\\n" + "=" * 80 + "\\n")
    
    print("Test Case 4: Invalid HTTP method")
    print(handle_api_request("http://localhost:3000", "TRACE", "Content-Type", "/api/data"))
    print("\\n" + "=" * 80 + "\\n")
    
    print("Test Case 5: POST request to valid endpoint")
    print(handle_api_request("https://example.com", "POST", "Content-Type, Authorization", "/api/data"))
