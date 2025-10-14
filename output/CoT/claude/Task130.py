
from typing import Dict, Set, Optional, Tuple
import re

class Task130:
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
    
    MAX_AGE: int = 3600

    @staticmethod
    def sanitize_header(header: Optional[str]) -> Optional[str]:
        """Sanitize header value to prevent injection attacks"""
        if header is None:
            return None
        
        # Remove control characters
        sanitized = re.sub(r'[\\x00-\\x1F\\x7F]', '', header).strip()
        
        # Check for CRLF injection
        if '\\r' in sanitized or '\\n' in sanitized:
            return None
        
        return sanitized

    @staticmethod
    def validate_requested_headers(requested_headers: str) -> bool:
        """Validate that requested headers are in the allowed list"""
        headers = [h.strip().lower() for h in requested_headers.split(',')]
        allowed_lower = {h.lower() for h in Task130.ALLOWED_HEADERS}
        
        for header in headers:
            if header and header not in allowed_lower:
                return False
        return True

    @staticmethod
    def handle_cors(origin: Optional[str], method: Optional[str], 
                   request_headers: Optional[str] = None) -> Tuple[bool, Dict[str, str], str]:
        """\n        Handle CORS request and return appropriate headers\n        \n        Returns:\n            Tuple of (allowed: bool, headers: dict, message: str)\n        """
        response_headers: Dict[str, str] = {}
        
        # Validate and sanitize origin
        sanitized_origin = Task130.sanitize_header(origin)
        if not sanitized_origin:
            return False, response_headers, "Invalid origin"
        
        # Check if origin is allowed
        if sanitized_origin not in Task130.ALLOWED_ORIGINS:
            return False, response_headers, "Origin not allowed"
        
        # Validate method
        sanitized_method = Task130.sanitize_header(method)
        if not sanitized_method or sanitized_method.upper() not in Task130.ALLOWED_METHODS:
            return False, response_headers, "Method not allowed"
        
        # Set CORS headers
        response_headers["Access-Control-Allow-Origin"] = sanitized_origin
        response_headers["Access-Control-Allow-Methods"] = ", ".join(Task130.ALLOWED_METHODS)
        response_headers["Access-Control-Allow-Headers"] = ", ".join(Task130.ALLOWED_HEADERS)
        response_headers["Access-Control-Max-Age"] = str(Task130.MAX_AGE)
        response_headers["Access-Control-Allow-Credentials"] = "true"
        
        # Security headers
        response_headers["X-Content-Type-Options"] = "nosniff"
        response_headers["X-Frame-Options"] = "DENY"
        response_headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Handle preflight request
        if sanitized_method.upper() == "OPTIONS":
            if request_headers:
                sanitized_req_headers = Task130.sanitize_header(request_headers)
                if sanitized_req_headers and not Task130.validate_requested_headers(sanitized_req_headers):
                    return False, response_headers, "Requested headers not allowed"
            return True, response_headers, "Preflight request approved"
        
        return True, response_headers, "CORS request approved"


def main():
    print("=== CORS Implementation Test Cases ===\\n")
    
    # Test case 1: Valid GET request
    print("Test 1: Valid GET request from allowed origin")
    allowed, headers, message = Task130.handle_cors("https://example.com", "GET")
    print(f"Allowed: {allowed}")
    print(f"Message: {message}")
    print("Headers:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    print()
    
    # Test case 2: Valid OPTIONS preflight request
    print("Test 2: Valid OPTIONS preflight request")
    allowed, headers, message = Task130.handle_cors(
        "https://app.example.com", "OPTIONS", "Content-Type, Authorization"
    )
    print(f"Allowed: {allowed}")
    print(f"Message: {message}")
    print("Headers:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    print()
    
    # Test case 3: Invalid origin
    print("Test 3: Request from non-allowed origin")
    allowed, headers, message = Task130.handle_cors("https://malicious.com", "GET")
    print(f"Allowed: {allowed}")
    print(f"Message: {message}")
    print()
    
    # Test case 4: Invalid method
    print("Test 4: Request with non-allowed method")
    allowed, headers, message = Task130.handle_cors("https://example.com", "TRACE")
    print(f"Allowed: {allowed}")
    print(f"Message: {message}")
    print()
    
    # Test case 5: Valid POST request from localhost
    print("Test 5: Valid POST request from localhost")
    allowed, headers, message = Task130.handle_cors(
        "http://localhost:3000", "POST", "Content-Type"
    )
    print(f"Allowed: {allowed}")
    print(f"Message: {message}")
    print("Headers:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    print()


if __name__ == "__main__":
    main()
