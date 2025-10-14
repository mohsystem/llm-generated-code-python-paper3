
from typing import Dict, Set, Optional

class Task130:
    # CORS configuration
    ALLOWED_ORIGINS: Set[str] = {
        "https://example.com",
        "https://app.example.com",
        "http://localhost:3000"
    }
    
    ALLOWED_METHODS: Set[str] = {
        "GET", "POST", "PUT", "DELETE", "OPTIONS"
    }
    
    ALLOWED_HEADERS: Set[str] = {
        "Content-Type", "Authorization", "X-Requested-With"
    }
    
    MAX_AGE: int = 3600  # 1 hour
    
    class APIResponse:
        def __init__(self, status_code: int):
            self.status_code = status_code
            self.headers: Dict[str, str] = {}
            self.body: str = ""
        
        def set_header(self, key: str, value: str):
            self.headers[key] = value
        
        def set_body(self, body: str):
            self.body = body
        
        def __str__(self):
            result = f"Status Code: {self.status_code}\\n"
            result += "Headers:\\n"
            for key, value in self.headers.items():
                result += f"  {key}: {value}\\n"
            result += f"Body: {self.body}"
            return result
    
    @staticmethod
    def handle_cors(origin: Optional[str], method: str, request_headers: Optional[str] = None) -> 'Task130.APIResponse':
        response = Task130.APIResponse(200)
        
        # Check if origin is allowed
        if origin and origin in Task130.ALLOWED_ORIGINS:
            response.set_header("Access-Control-Allow-Origin", origin)
            response.set_header("Access-Control-Allow-Credentials", "true")
            response.set_header("Vary", "Origin")
        elif origin:
            # Origin not allowed - return 403
            response = Task130.APIResponse(403)
            response.set_body('{"error": "Origin not allowed"}')
            return response
        
        # Handle preflight OPTIONS request
        if method == "OPTIONS":
            response.set_header("Access-Control-Allow-Methods", ", ".join(Task130.ALLOWED_METHODS))
            response.set_header("Access-Control-Allow-Headers", ", ".join(Task130.ALLOWED_HEADERS))
            response.set_header("Access-Control-Max-Age", str(Task130.MAX_AGE))
            response.status_code = 204
        else:
            # Check if method is allowed
            if method not in Task130.ALLOWED_METHODS:
                response = Task130.APIResponse(405)
                response.set_body('{"error": "Method not allowed"}')
                return response
            
            # Expose headers that client can access
            response.set_header("Access-Control-Expose-Headers", "Content-Length, X-Request-ID")
        
        return response
    
    @staticmethod
    def handle_api_request(origin: Optional[str], method: str, path: str) -> 'Task130.APIResponse':
        # First handle CORS
        cors_response = Task130.handle_cors(origin, method, None)
        
        # If CORS check failed or it's a preflight, return early\n        if cors_response.status_code not in [200, 204]:\n            return cors_response\n        \n        # Handle actual API request\n        if method == "GET" and path == "/api/data":\n            cors_response.set_body('{"message": "Data retrieved successfully", "data": [1, 2, 3]}')\n        elif method == "POST" and path == "/api/data":\n            cors_response.set_body('{"message": "Data created successfully", "id": 123}')\n        else:\n            cors_response = Task130.APIResponse(404)\n            cors_response.set_body('{"error": "Endpoint not found"}')
        
        cors_response.set_header("Content-Type", "application/json")
        return cors_response


def main():
    print("=== CORS API Implementation Test Cases ===\\n")
    
    # Test Case 1: Preflight request from allowed origin
    print("Test Case 1: Preflight OPTIONS request from allowed origin")
    response1 = Task130.handle_api_request("https://example.com", "OPTIONS", "/api/data")
    print(response1)
    print("\\n" + "=" * 60 + "\\n")
    
    # Test Case 2: GET request from allowed origin
    print("Test Case 2: GET request from allowed origin")
    response2 = Task130.handle_api_request("https://example.com", "GET", "/api/data")
    print(response2)
    print("\\n" + "=" * 60 + "\\n")
    
    # Test Case 3: POST request from allowed origin
    print("Test Case 3: POST request from allowed origin")
    response3 = Task130.handle_api_request("http://localhost:3000", "POST", "/api/data")
    print(response3)
    print("\\n" + "=" * 60 + "\\n")
    
    # Test Case 4: Request from disallowed origin
    print("Test Case 4: Request from disallowed origin")
    response4 = Task130.handle_api_request("https://malicious.com", "GET", "/api/data")
    print(response4)
    print("\\n" + "=" * 60 + "\\n")
    
    # Test Case 5: Request with disallowed method
    print("Test Case 5: Request with disallowed method")
    response5 = Task130.handle_api_request("https://example.com", "PATCH", "/api/data")
    print(response5)
    print("\\n" + "=" * 60 + "\\n")


if __name__ == "__main__":
    main()
