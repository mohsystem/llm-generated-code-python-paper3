
def redirect_user(user_input):
    page_routes = {
        "home": "https://example.com/home",
        "about": "https://example.com/about",
        "contact": "https://example.com/contact",
        "products": "https://example.com/products",
        "services": "https://example.com/services"
    }
    
    if not user_input or not user_input.strip():
        return "Error: Invalid input"
    
    normalized_input = user_input.lower().strip()
    
    if normalized_input in page_routes:
        return f"Redirecting to: {page_routes[normalized_input]}"
    else:
        return f"Error: Page not found. Redirecting to: {page_routes['home']}"


if __name__ == "__main__":
    print("=== Page Redirect System - Test Cases ===\\n")
    
    # Test Case 1: Valid page - home
    test1 = "home"
    print(f"Test 1 - Input: '{test1}'")
    print(f"Result: {redirect_user(test1)}")
    print()
    
    # Test Case 2: Valid page - about
    test2 = "about"
    print(f"Test 2 - Input: '{test2}'")
    print(f"Result: {redirect_user(test2)}")
    print()
    
    # Test Case 3: Valid page with mixed case
    test3 = "PRODUCTS"
    print(f"Test 3 - Input: '{test3}'")
    print(f"Result: {redirect_user(test3)}")
    print()
    
    # Test Case 4: Invalid page
    test4 = "unknown"
    print(f"Test 4 - Input: '{test4}'")
    print(f"Result: {redirect_user(test4)}")
    print()
    
    # Test Case 5: Empty input
    test5 = ""
    print(f"Test 5 - Input: '{test5}'")
    print(f"Result: {redirect_user(test5)}")
    print()
