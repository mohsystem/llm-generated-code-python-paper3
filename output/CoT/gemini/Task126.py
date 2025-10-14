def redirect_user(choice: str) -> str:
    """
    Redirects a user based on a string choice.
    The comparison is case-insensitive.

    Args:
        choice: The user's page selection (e.g., "home", "about").

    Returns:
        A string indicating the redirection URL or an error message.
    """
    if not isinstance(choice, str) or not choice.strip():
        return "Error: Page not found (404)"

    # A dictionary to map choices to pages
    # .get() provides a safe way to access keys and a default value
    pages = {
        "home": "Redirecting to /home.html",
        "about": "Redirecting to /about.html",
        "contact": "Redirecting to /contact.html",
        "products": "Redirecting to /products.html"
    }
    
    # Use .get() with a default value for the "not found" case
    return pages.get(choice.lower(), "Error: Page not found (404)")

# Main block with test cases
if __name__ == "__main__":
    test_cases = ["home", "About", "products", "login", ""]
    
    print("--- Python Test Cases ---")
    for test in test_cases:
        print(f'Input: "{test}" -> Output: {redirect_user(test)}')