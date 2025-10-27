import os
import re
import shutil
from pathlib import Path

# --- Router and Decorator Setup ---
ROUTES = {}

def route(url_pattern):
    """A decorator that registers a function to a URL pattern."""
    def decorator(func):
        ROUTES[re.compile(f"^{url_pattern}$")] = func
        return func
    return decorator

# --- Application Logic ---
IMAGE_DIR = Path("images")

@route(r"/images/(?P<filename>[a-zA-Z0-9_.-]+)")
def serve_image(filename):
    """
    Checks if a file exists in the images folder and returns its content.
    Includes security checks to prevent path traversal.
    """
    # --- Security Check: Path Traversal ---
    # os.path.basename strips any leading directory components from the filename.
    # This is a primary defense against directory traversal attacks like "../secret.txt".
    safe_basename = os.path.basename(filename)
    if safe_basename != filename:
        return "HTTP 400: Invalid filename (directory components are not allowed)."

    # Construct the full, intended path
    file_path = IMAGE_DIR.resolve() / safe_basename
    
    # Final check: Ensure the resolved path is still within our image directory.
    # This protects against more complex attacks like symlink vulnerabilities.
    if IMAGE_DIR.resolve() not in file_path.parents:
         return "HTTP 403: Forbidden - Access outside of image directory is not allowed."

    if file_path.is_file():
        try:
            # Simulate sending file to browser by returning its content
            content = file_path.read_text()
            return f"HTTP 200: Serving content of {filename}: {content}"
        except Exception as e:
            return f"HTTP 500: Could not read file. Error: {e}"
    else:
        return "HTTP 404: File not found."

def dispatch(url):
    """Finds the matching route and calls its handler function."""
    for pattern, handler in ROUTES.items():
        match = pattern.match(url)
        if match:
            # Pass captured groups from the URL as keyword arguments to the handler
            return handler(**match.groupdict())
    return "HTTP 404: Route not found."

# --- Main method with test cases ---
def main():
    """Sets up the environment, runs tests, and cleans up."""
    # 1. Setup: Create a dummy images directory and files
    if not IMAGE_DIR.exists():
        IMAGE_DIR.mkdir()
    (IMAGE_DIR / "cat.jpg").write_text("This is a cat image")
    (IMAGE_DIR / "dog_1.png").write_text("This is a dog image")

    print("--- Running 5 Test Cases ---")

    # Test Case 1: Valid file request
    print("Test 1 (Valid): /images/cat.jpg")
    print(f"Response: {dispatch('/images/cat.jpg')}\n")

    # Test Case 2: File does not exist
    print("Test 2 (Not Found): /images/horse.gif")
    print(f"Response: {dispatch('/images/horse.gif')}\n")

    # Test Case 3: Path traversal attempt
    print("Test 3 (Path Traversal): /images/../secret.txt")
    print(f"Response: {dispatch('/images/../secret.txt')}\n") # Will fail regex

    # Test Case 4: Another path traversal attempt (different format)
    # The basename check will catch this even if regex allowed it.
    print("Test 4 (Path Traversal 2): /images/..%2fsecret.txt")
    print(f"Response: dispatch('/images/..%2fsecret.txt')\n") # Will fail regex

    # Test Case 5: Invalid route
    print("Test 5 (Invalid Route): /videos/movie.mp4")
    print(f"Response: {dispatch('/videos/movie.mp4')}\n")

    # Cleanup
    if IMAGE_DIR.exists():
        shutil.rmtree(IMAGE_DIR)

if __name__ == "__main__":
    main()