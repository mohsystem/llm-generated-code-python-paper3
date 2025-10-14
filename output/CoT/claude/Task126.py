
import re
from typing import Dict, Optional

class Task126:
    ALLOWED_PAGES: Dict[str, str] = {
        'home': '/home',
        'about': '/about',
        'contact': '/contact',
        'services': '/services',
        'profile': '/profile'
    }
    
    @staticmethod
    def redirect_user(user_input: Optional[str]) -> str:
        """\n        Securely redirect users based on validated input.\n        \n        Args:\n            user_input: The page identifier provided by user\n            \n        Returns:\n            Redirect message with validated page path\n        """
        if not user_input or not user_input.strip():
            return "Error: Invalid input. Redirecting to default page: /home"
        
        # Sanitize input: convert to lowercase and remove special characters
        sanitized_input = user_input.strip().lower()
        sanitized_input = re.sub(r'[^a-z0-9]', '', sanitized_input)
        
        # Check against whitelist
        if sanitized_input in Task126.ALLOWED_PAGES:
            return f"Redirecting to: {Task126.ALLOWED_PAGES[sanitized_input]}"
        else:
            return "Error: Page not found. Redirecting to default page: /home"


def main():
    print("=== User Redirection System (Python) ===\\n")
    
    # Test cases
    test_cases = [
        "home",
        "about",
        "contact",
        "invalid_page",
        "../../../etc/passwd"
    ]
    
    for test_case in test_cases:
        print(f'Input: "{test_case}"')
        print(f"Result: {Task126.redirect_user(test_case)}")
        print()


if __name__ == "__main__":
    main()
