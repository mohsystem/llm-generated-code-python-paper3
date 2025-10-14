import re

def is_valid_url(url: str) -> bool:
    """
    Validates a URL string using a regular expression.
    Checks for http/https protocol and a valid domain structure.
    """
    if not isinstance(url, str):
        return False
        
    # Regex to check for a valid URL format.
    # It requires http or https, a domain name with at least one dot, and a TLD of 2+ letters.
    regex = re.compile(
        r'^(https?://)'  # http:// or https://
        r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'  # domain name...
        r'(:\d+)?'  # optional port
        r'(/.*)?$'  # optional path
    )
    
    return re.match(regex, url) is not None

def main():
    """ Main function with test cases """
    test_urls = [
        "https://www.google.com",
        "http://example.org/path?name=value",
        "ftp://example.com",
        "https://example..com",
        "http://invalid",
        "just a string"
    ]
    
    print("--- Python URL Validation ---")
    for url in test_urls:
        result = "valid" if is_valid_url(url) else "invalid"
        print(f'URL: "{url}" is {result}')

if __name__ == "__main__":
    main()