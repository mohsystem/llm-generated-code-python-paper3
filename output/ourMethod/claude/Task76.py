
import sys
import re
import ssl
import urllib.request
import urllib.error
from typing import Optional

MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB
TIMEOUT_SECONDS = 10
TITLE_PATTERN = re.compile(r'<title[^>]*>([^<]*)</title>', re.IGNORECASE)


def extract_title(url_string: str) -> str:
    if not url_string or not url_string.strip():
        raise ValueError("URL cannot be null or empty")
    
    url_string = url_string.strip()
    
    if not url_string.lower().startswith("https://"):
        raise ValueError("Only HTTPS URLs are allowed")
    
    if len(url_string) > 2048:
        raise ValueError("URL exceeds maximum allowed length")
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        request = urllib.request.Request(
            url_string,
            headers={'User-Agent': 'TitleExtractor/1.0'}
        )
        
        with urllib.request.urlopen(
            request,
            timeout=TIMEOUT_SECONDS,
            context=context
        ) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP request failed with code: {response.status}")
            
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type.lower():
                raise RuntimeError("Response is not HTML content")
            
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > MAX_CONTENT_LENGTH:
                raise RuntimeError("Content exceeds maximum allowed size")
            
            content_bytes = response.read(MAX_CONTENT_LENGTH + 1)
            if len(content_bytes) > MAX_CONTENT_LENGTH:
                raise RuntimeError("Content exceeds maximum allowed size")
            
            content = content_bytes.decode('utf-8', errors='ignore')
        
        match = TITLE_PATTERN.search(content)
        if match:
            title = match.group(1).strip()
            return title if title else "No title found"
        
        return "No title found"
    
    except ValueError as e:
        raise e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to extract title: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"Failed to extract title: {str(e)}")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python solution.py <https-url>", file=sys.stderr)
        sys.exit(1)
    
    test_urls = [
        sys.argv[1],
        "https://www.example.com",
        "https://www.wikipedia.org",
        "https://www.github.com",
        "https://www.google.com"
    ]
    
    for url in test_urls:
        try:
            title = extract_title(url)
            print(f"URL: {url}")
            print(f"Title: {title}")
            print()
        except Exception as e:
            print(f"Error for URL {url}: {str(e)}", file=sys.stderr)
            print(file=sys.stderr)


if __name__ == "__main__":
    main()
