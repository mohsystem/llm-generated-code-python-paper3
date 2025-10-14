import json
from typing import Dict, Optional, Set, Any

# Whitelist of allowed origins. Using a wildcard (*) is discouraged for security reasons.
ALLOWED_ORIGINS: Set[str] = {
    "https://example.com",
    "https://trusted.site.org"
}
# Define allowed methods and headers for preflight requests.
ALLOWED_METHODS: str = "GET, POST, OPTIONS"
ALLOWED_HEADERS: str = "Content-Type, Authorization"
MAX_AGE: str = "86400"  # 24 hours

def handle_cors_request(method: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Handles a request by applying Cross-Origin Resource Sharing (CORS) rules.
    This function simulates a server-side API endpoint's CORS logic.

    Args:
        method: The HTTP method (e.g., "GET", "OPTIONS").
        headers: A dictionary of request headers. Assumes header keys are lowercase.
    
    Returns:
        A dictionary representing the HTTP response.
    """
    origin = headers.get("origin")
    
    response_headers: Dict[str, str] = {}
    
    # Rule #3: Validate input. The origin must be from the predefined whitelist.
    is_origin_allowed = origin is not None and origin in ALLOWED_ORIGINS

    if not is_origin_allowed:
        # If the origin is not allowed, or no origin header was provided,
        # do not add any CORS headers and return an error.
        return {
            "status_code": 403,
            "headers": {},
            "body": json.dumps({"error": "CORS policy does not allow this origin."})
        }
        
    # The origin is allowed, so add the primary CORS response header.
    response_headers["Access-Control-Allow-Origin"] = origin

    # Handle preflight (OPTIONS) request
    if method.upper() == "OPTIONS":
        response_headers["Access-Control-Allow-Methods"] = ALLOWED_METHODS
        response_headers["Access-Control-Allow-Headers"] = ALLOWED_HEADERS
        response_headers["Access-Control-Max-Age"] = MAX_AGE
        return {
            "status_code": 204,
            "headers": response_headers,
            "body": ""
        }

    # Handle actual API requests (e.g., GET, POST)
    if method.upper() in ["GET", "POST"]:
        response_headers["Content-Type"] = "application/json"
        return {
            "status_code": 200,
            "headers": response_headers,
            "body": json.dumps({"data": "some protected data"})
        }

    # If the method is not OPTIONS, GET, or POST, it's not allowed.
    # The Access-Control-Allow-Origin header is still sent because the origin was valid.
    return {
        "status_code": 405,
        "headers": response_headers,
        "body": json.dumps({"error": "Method not allowed."})
    }

def print_response(response: Dict[str, Any]):
    print(f"Status: {response['status_code']}")
    print("Headers:")
    if not response['headers']:
        print("  (none)")
    else:
        for key, value in response['headers'].items():
            print(f"  {key}: {value}")
    print("Body:")
    print(response['body'])

if __name__ == '__main__':
    print("--- Test Case 1: Valid GET request from an allowed origin ---")
    request1 = {"method": "GET", "headers": {"origin": "https://example.com"}}
    response1 = handle_cors_request(request1["method"], request1["headers"])
    print_response(response1)
    print("\n----------------------------------------------------------\n")

    print("--- Test Case 2: Valid Preflight (OPTIONS) request from an allowed origin ---")
    request2 = {"method": "OPTIONS", "headers": {"origin": "https://trusted.site.org"}}
    response2 = handle_cors_request(request2["method"], request2["headers"])
    print_response(response2)
    print("\n----------------------------------------------------------\n")
    
    print("--- Test Case 3: Request from a disallowed origin ---")
    request3 = {"method": "GET", "headers": {"origin": "https://malicious.com"}}
    response3 = handle_cors_request(request3["method"], request3["headers"])
    print_response(response3)
    print("\n----------------------------------------------------------\n")

    print("--- Test Case 4: Request with a missing Origin header ---")
    request4 = {"method": "GET", "headers": {}}
    response4 = handle_cors_request(request4["method"], request4["headers"])
    print_response(response4)
    print("\n----------------------------------------------------------\n")
    
    print("--- Test Case 5: Request with a disallowed method (PUT) from an allowed origin ---")
    request5 = {"method": "PUT", "headers": {"origin": "https://example.com"}}
    response5 = handle_cors_request(request5["method"], request5["headers"])
    print_response(response5)
    print("\n----------------------------------------------------------\n")