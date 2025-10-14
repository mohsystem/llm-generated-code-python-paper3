
import re
from typing import Optional

ALLOWED_PAGES = {
    "home": "/pages/home.html",
    "about": "/pages/about.html",
    "contact": "/pages/contact.html",
    "products": "/pages/products.html",
    "services": "/pages/services.html"
}

SAFE_PAGE_PATTERN = re.compile(r'^[a-z0-9_-]+$')

def redirect_to_page(user_input: Optional[str]) -> str:
    if user_input is None or len(user_input) == 0:
        return "Error: Invalid input"
    
    sanitized_input = user_input.strip().lower()
    
    if len(sanitized_input) > 50:
        return "Error: Input too long"
    
    if not SAFE_PAGE_PATTERN.match(sanitized_input):
        return "Error: Invalid page name format"
    
    target_page = ALLOWED_PAGES.get(sanitized_input)
    
    if target_page is None:
        return "Error: Page not found"
    
    return f"Redirect to: {target_page}"

def main():
    print("Test Case 1:", redirect_to_page("home"))
    print("Test Case 2:", redirect_to_page("about"))
    print("Test Case 3:", redirect_to_page("invalid"))
    print("Test Case 4:", redirect_to_page("../../../etc/passwd"))
    print("Test Case 5:", redirect_to_page(None))

if __name__ == "__main__":
    main()
