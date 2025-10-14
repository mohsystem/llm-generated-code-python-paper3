
from typing import Optional
from urllib.parse import urlparse
import re

MAX_URL_LENGTH = 2048
VALID_SCHEME = re.compile(r'^(https?|ftp)$')
VALID_HOST = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')

def validate_url(url: Optional[str]) -> bool:
    if url is None or not isinstance(url, str) or not url:
        return False
    
    if len(url) > MAX_URL_LENGTH:
        return False
    
    trimmed_url = url.strip()
    if not trimmed_url:
        return False
    
    try:
        parsed = urlparse(trimmed_url)
        
        if not parsed.scheme or not VALID_SCHEME.match(parsed.scheme.lower()):
            return False
        
        if not parsed.netloc:
            return False
        
        hostname = parsed.hostname
        if not hostname:
            return False
        
        if not VALID_HOST.match(hostname):
            import socket
            try:
                socket.getaddrinfo(hostname, None)
            except (socket.gaierror, socket.error):
                return False
        
        if parsed.port is not None:
            if parsed.port < 1 or parsed.port > 65535:
                return False
        
        if parsed.path:
            if '..' in parsed.path or '//' in parsed.path or '\\\\' in parsed.path:\n                return False\n        \n        return True\n        \n    except (ValueError, AttributeError):\n        return False\n    except Exception:\n        return False\n\ndef main() -> None:\n    test_cases = [\n        "https://www.example.com",\n        "http://example.com/path/to/resource",\n        "ftp://ftp.example.com:21/file.txt",\n        "javascript:alert('xss')",\n        "http://.invalid..domain/path"\n    ]\n    \n    for test_url in test_cases:\n        result = validate_url(test_url)\n        print(f"URL: {test_url} -> Valid: {result}")\n\nif __name__ == "__main__":
    main()
