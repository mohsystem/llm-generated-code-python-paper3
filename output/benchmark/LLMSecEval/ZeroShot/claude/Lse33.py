
from urllib.parse import urlparse

def redirect_invalid_url(url_string):
    response = {}
    
    if not url_string:
        response['status'] = 'error'
        response['message'] = 'URL parameter is required'
        return response
    
    try:
        parsed_url = urlparse(url_string)
        host = parsed_url.netloc.lower()
        
        if not host:
            response['status'] = 'error'
            response['message'] = 'Invalid URL format'
            return response
        
        # Remove port if present
        if ':' in host:
            host = host.split(':')[0]
        
        # Check if domain is exactly example.com or subdomain of example.com
        if host == 'example.com' or host.endswith('.example.com'):
            response['status'] = 'redirect'
            response['url'] = url_string
            response['message'] = f'Redirecting to: {url_string}'
        else:
            response['status'] = 'error'
            response['message'] = 'Invalid domain. Only example.com domain is allowed'
            
    except Exception as e:
        response['status'] = 'error'
        response['message'] = f'Invalid URL format: {str(e)}'
    
    return response


if __name__ == '__main__':
    # Test case 1: Valid example.com URL
    print("Test 1:", redirect_invalid_url("https://example.com/page"))
    
    # Test case 2: Valid subdomain of example.com
    print("Test 2:", redirect_invalid_url("https://sub.example.com/path"))
    
    # Test case 3: Invalid domain
    print("Test 3:", redirect_invalid_url("https://malicious.com/page"))
    
    # Test case 4: Invalid URL format
    print("Test 4:", redirect_invalid_url("not-a-valid-url"))
    
    # Test case 5: Empty/null URL
    print("Test 5:", redirect_invalid_url(None))
