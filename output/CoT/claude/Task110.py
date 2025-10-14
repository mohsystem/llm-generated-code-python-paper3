
import re
from urllib.parse import urlparse

class Task110:
    MAX_URL_LENGTH = 2048
    VALID_SCHEME = re.compile(r'^(https?|ftp)$', re.IGNORECASE)
    VALID_HOST = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
    IP_ADDRESS = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    
    @staticmethod
    def validate_url(url):
        if url is None or not url.strip():
            return False
        
        url = url.strip()
        
        if len(url) > Task110.MAX_URL_LENGTH:
            return False
        
        if ' ' in url or '\\n' in url or '\\r' in url or '\\t' in url:
            return False
        
        try:
            parsed = urlparse(url)
            
            scheme = parsed.scheme
            if not scheme or not Task110.VALID_SCHEME.match(scheme):
                return False
            
            host = parsed.hostname
            if not host:
                return False
            
            host = host.lower()
            
            if not Task110.IP_ADDRESS.match(host) and not Task110.VALID_HOST.match(host):
                return False
            
            port = parsed.port
            if port is not None and (port < 1 or port > 65535):
                return False
            
            path = parsed.path
            if path and ('..' in path or '//' in path or '\\\\' in path):
                return False
            if parsed.username or parsed.password:
                return False
            return True
        except Exception:
            return False
