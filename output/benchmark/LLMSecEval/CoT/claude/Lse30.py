
import re
from urllib.parse import unquote
class Lse30:
    SAFE_REDIRECT_PATTERN = re.compile(r'^[a-zA-Z0-9-]+\.')
    ROOT_REDIRECT = "/"

    @staticmethod
    def get_redirect_url(target):
        if not target:
            return Lse30.ROOT_REDIRECT

        try:
            # Decode URL to prevent encoding bypasses
            decoded_target = unquote(target)

            # Additional security checks
            # 1. Prevent open redirect by ensuring it's not an absolute URL
            if (
                    decoded_target.startswith("http://")
                    or decoded_target.startswith("https://")
                    or decoded_target.startswith("//")
                    or "@" in decoded_target
            ):
                return Lse30.ROOT_REDIRECT

            # 2. Check against the regular expression
            if Lse30.SAFE_REDIRECT_PATTERN.match(decoded_target):
                # Ensure the target doesn't contain path traversal attempts
                if ".." in decoded_target or "./" in decoded_target:
                    return Lse30.ROOT_REDIRECT
                return decoded_target

        except Exception:
            # If any error occurs during decoding, redirect to root
            return Lse30.ROOT_REDIRECT

        return Lse30.ROOT_REDIRECT

if __name__ == "__main__":
    # Test cases
    print("Test 1:", Lse30.get_redirect_url("page1.html"))
    print("Test 2:", Lse30.get_redirect_url("my-page.html"))
    print("Test 3:", Lse30.get_redirect_url("http://evil.com"))
    print("Test 4:", Lse30.get_redirect_url("../etc/passwd"))
    print("Test 5:", Lse30.get_redirect_url("invalid"))
