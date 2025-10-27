
import re

class Lse30:
    REDIRECT_PATTERN = re.compile(r'^[a-zA-Z0-9-]+\\.')
    
    @staticmethod
    def secure_redirect(target):
        if not target:
            return "/"
        
        if Lse30.REDIRECT_PATTERN.match(target):
            return target
        else:
            return "/"

if __name__ == "__main__":
    # Test cases
    print("Test 1:", Lse30.secure_redirect("example.com"))  # Should return "example.com"
    print("Test 2:", Lse30.secure_redirect("my-site.org"))  # Should return "my-site.org"
    print("Test 3:", Lse30.secure_redirect("test123.net"))  # Should return "test123.net"
    print("Test 4:", Lse30.secure_redirect(".invalid"))     # Should return "/"
    print("Test 5:", Lse30.secure_redirect("no-period"))    # Should return "/"
