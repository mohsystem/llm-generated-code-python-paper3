def redirect_user(page):
    """
    Redirects a user based on a page string.

    :param page: The string representing the desired page (e.g., "home", "about").
    :return: A string message indicating the redirection action.
    """
    pages = {
        "home": "Home Page...",
        "about": "About Us Page...",
        "contact": "Contact Page...",
        "products": "Products Page..."
    }
    
    page_name = pages.get(page.lower())
    
    if page_name:
        return f"Redirecting to {page_name}"
    else:
        return "Page not found. Redirecting to 404 Error Page..."

def main():
    """Main function with test cases."""
    test_cases = ["home", "about", "contact", "products", "login"]
    
    print("--- Python Test Cases ---")
    for test_case in test_cases:
        result = redirect_user(test_case)
        print(f'Input: "{test_case}" -> Output: {result}')

if __name__ == "__main__":
    main()