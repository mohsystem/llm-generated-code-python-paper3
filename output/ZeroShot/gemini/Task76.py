import re
import requests

def extract_page_title(url):
    """
    Fetches an HTTPS URL and extracts the content of the <title> tag.

    Args:
        url: The HTTPS URL to fetch.
    
    Returns:
        The extracted page title, or an error message.
    """
    # 1. Input Validation: Ensure URL is a string and uses HTTPS.
    if not isinstance(url, str) or not url.lower().startswith("https://"):
        return "Error: Invalid or insecure URL provided. Please use HTTPS."

    try:
        # 2. Setup Request: Use a timeout and a descriptive User-Agent.
        headers = {'User-Agent': 'Python Requests Bot/1.0'}
        # Certificate verification is enabled by default in `requests`.
        response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)

        # 3. Handle HTTP Errors: Raise an exception for 4xx or 5xx status codes.
        response.raise_for_status()

        html_content = response.text

        # 4. Extract Title using a simple, non-greedy regex.
        # re.IGNORECASE makes the search case-insensitive.
        match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
        
        if match:
            # group(1) contains the text captured by (.*?)
            return match.group(1).strip()
        else:
            return "Error: Title tag not found."

    # 5. Handle various exceptions gracefully.
    except requests.exceptions.Timeout:
        return "Error: Request timed out."
    except requests.exceptions.HTTPError as e:
        return f"Error: HTTP Error - Status code {e.response.status_code}"
    except requests.exceptions.RequestException as e:
        # For DNS errors, connection errors, etc.
        return f"Error: A request exception occurred - {type(e).__name__}"
    except Exception as e:
        return f"Error: An unexpected error occurred - {e}"

def main():
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "https://github.com/nonexistent/repo",  # 404 test
        "https://thissitedoesnotexist12345.com",  # DNS error
        "http://www.google.com"  # Insecure URL test
    ]
    
    for url in test_urls:
        print(f"Testing URL: {url}")
        title = extract_page_title(url)
        print(f"Page Title: {title}")
        print("--------------------")

if __name__ == "__main__":
    main()