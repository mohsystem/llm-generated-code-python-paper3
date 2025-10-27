
import re

def process_redirect(target):
    # Regular expression: one or more alphanumeric characters or hyphens followed by a period
    regex = r'^[a-zA-Z0-9-]+\\..*'
    
    if re.match(regex, target):
        return target
    else:
        return "/"

def main():
    # Test cases
    test_cases = [
        "example.com",
        "test-site.org",
        "my-page.html",
        ".invalid",
        "noperiod"
    ]
    
    print("Python Test Results:")
    for test_case in test_cases:
        result = process_redirect(test_case)
        print(f"Input: '{test_case}' -> Redirect to: '{result}'")

if __name__ == "__main__":
    main()
