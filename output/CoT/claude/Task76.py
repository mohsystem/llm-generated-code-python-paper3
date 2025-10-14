
import sys
import re
import urllib.request
import urllib.parse
import ssl
from urllib.error import URLError, HTTPError

class Task76:
    TIMEOUT = 10  # 10 seconds
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB
    TITLE_PATTERN = re.compile(r'<title[^>]*>\\s*([^<]+)\\s*</title>', re.IGNORECASE)
    
    @staticmethod
    def extract_page_title(url_string):
        """Extract page title from HTTPS URL"""
        if not url_string or not url_string.strip():
            return "Error: URL cannot be empty"
        
        # Validate URL format and ensure HTTPS
        if not Task76._is_valid_https_url(url_string):
            return "Error: Invalid URL or non-HTTPS URL provided"
        
        try:
            # Parse URL
            parsed_url = urllib.parse.urlparse(url_string)
            
            # Create secure SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Create request with security headers
            request = urllib.request.Request(
                url_string,
                headers={
                    'User-Agent': 'SecurePageTitleExtractor/1.0',
                    'Accept': 'text/html'
                }
            )
            
            # Make request
            with urllib.request.urlopen(request, timeout=Task76.TIMEOUT, context=context) as response:
                # Check response code
                if response.status != 200:
                    return f"Error: HTTP {response.status}"
                
                # Check content length
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) > Task76.MAX_CONTENT_LENGTH:
                    return "Error: Content too large"
                
                # Read response with size limit
                content = response.read(Task76.MAX_CONTENT_LENGTH)
                html = content.decode('utf-8', errors='ignore')
                
                # Extract title
                return Task76._extract_title_from_html(html)
                
        except HTTPError as e:
            return f"Error: HTTP {e.code}"
        except URLError as e:
            return f"Error: {Task76._sanitize_error_message(str(e.reason))}"
        except Exception as e:
            return f"Error: {Task76._sanitize_error_message(str(e))}"
    
    @staticmethod
    def _is_valid_https_url(url):
        """Validate HTTPS URL and prevent SSRF attacks"""
        if not url or not url.lower().startswith('https://'):
            return False
        
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname
            
            if not host:
                return False
            
            # Block localhost and private IP ranges
            blocked_hosts = ['localhost', '127.0.0.1', '::1']
            if host in blocked_hosts:
                return False
            
            if host.startswith('192.168.') or host.startswith('10.') or host.startswith('172.'):
                return False
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def _extract_title_from_html(html):
        """Extract title from HTML content"""
        if not html:
            return "No title found"
        
        match = Task76.TITLE_PATTERN.search(html)
        if match:
            title = match.group(1)
            return Task76._sanitize_output(title)
        
        return "No title found"
    
    @staticmethod
    def _sanitize_output(text):
        """Sanitize output to prevent injection"""
        if not text:
            return ""
        # Remove HTML entities and trim
        text = re.sub(r'&[a-zA-Z0-9#]+;', '', text)
        text = re.sub(r'[\\r\\n]+', ' ', text)
        return text.strip()
    
    @staticmethod
    def _sanitize_error_message(message):
        """Remove sensitive information from error messages"""
        if not message:
            return "Unknown error"
        # Remove URLs from error messages
        message = re.sub(r'https?://[^\\s]+', '[URL]', message)
        return message[:100]


def main():
    if len(sys.argv) < 2:
        print("Usage: python Task76.py <https-url>")
        print("\\nTest cases:")
        
        # Test cases
        test_urls = [
            "https://www.example.com",
            "https://www.google.com",
            "http://www.example.com",  # Should fail - not HTTPS
            "https://localhost",  # Should fail - localhost blocked
            "invalid-url"  # Should fail - invalid format
        ]
        
        for url in test_urls:
            print(f"\\nURL: {url}")
            print(f"Title: {Task76.extract_page_title(url)}")
    else:
        result = Task76.extract_page_title(sys.argv[1])
        print(result)


if __name__ == "__main__":
    main()
