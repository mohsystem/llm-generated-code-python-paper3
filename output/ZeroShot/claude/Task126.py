
def redirect_user(user_input):
    valid_pages = {
        "home": "/home",
        "about": "/about",
        "contact": "/contact",
        "services": "/services",
        "products": "/products"
    }
    
    if user_input is None or not user_input.strip():
        return "Invalid input. Redirecting to default page: /home"
    
    sanitized_input = user_input.strip().lower()
    
    if sanitized_input in valid_pages:
        return f"Redirecting to: {valid_pages[sanitized_input]}"
    else:
        return "Page not found. Redirecting to default page: /home"


if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    print(redirect_user("home"))
    print()
    
    print("Test Case 2:")
    print(redirect_user("about"))
    print()
    
    print("Test Case 3:")
    print(redirect_user("invalidpage"))
    print()
    
    print("Test Case 4:")
    print(redirect_user(""))
    print()
    
    print("Test Case 5:")
    print(redirect_user("PRODUCTS"))
    print()
