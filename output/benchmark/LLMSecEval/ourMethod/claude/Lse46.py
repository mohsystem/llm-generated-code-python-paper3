
import os
from pathlib import Path
from urllib.parse import unquote
from flask import Flask, request, send_file, abort
import io

app = Flask(__name__)

# Trusted base directory for images - must be absolute
BASE_DIR = Path("images").resolve()
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

# Ensure base directory exists
BASE_DIR.mkdir(parents=True, exist_ok=True)

# Decorator: associates /img URL with img() function
@app.route('/img')
def img_endpoint():
    """HTTP endpoint handler for /img"""
    # Get name parameter from URL query string
    name = request.args.get('name')
    
    if not name:
        abort(400, "Missing name parameter")
    
    try:
        # Call img() function to get file content
        file_content = img(name)
        # Return file content as response
        return send_file(
            io.BytesIO(file_content),
            mimetype='application/octet-stream',
            as_attachment=False
        )
    except (ValueError, PermissionError, OSError) as e:
        abort(400, "Bad request")
    except FileNotFoundError:
        abort(404, "Not found")
    except Exception:
        abort(500, "Internal error")
def img(name):
    """
    Opens and returns file content from images directory.
    Implements secure file access with path validation.
    """
    # Input validation: reject null, empty, or suspicious names
    if not name or not isinstance(name, str):
        raise ValueError("Invalid file name")

    # Decode URL-encoded input
    decoded_name = unquote(name)

    # Sanitize: reject path traversal attempts and absolute paths
    if '..' in decoded_name or '/' in decoded_name or '\\' in decoded_name or decoded_name.startswith('.'):
        raise PermissionError("Invalid file name: path traversal not allowed")

    # Construct path relative to base directory
    requested_path = (BASE_DIR / decoded_name).resolve()

    # Verify the resolved path is still within base directory
    if not requested_path.is_relative_to(BASE_DIR):
        raise PermissionError("Access denied: path outside base directory")

    # Open file with follow_symlinks=False to prevent symlink attacks
    # Using os.open for low-level control, then wrapping with fdopen
    try:
        # Open with O_RDONLY and O_NOFOLLOW (no symlink following)
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW

        fd = os.open(requested_path, flags)
    except OSError as e:
        if e.errno == 2:  # ENOENT
            raise FileNotFoundError("File not found")
        elif e.errno == 40:  # ELOOP - too many symlinks
            raise PermissionError("Symlink not allowed")
        raise

    try:
        # Validate file attributes after opening (TOCTOU prevention)
        stat_info = os.fstat(fd)

        # Reject if not a regular file
        import stat as stat_module
        if not stat_module.S_ISREG(stat_info.st_mode):
            raise PermissionError("Not a regular file")

        # Check file size limit
        if stat_info.st_size > MAX_FILE_SIZE or stat_info.st_size < 0:
            raise PermissionError("File size exceeds limit or is invalid")

        # Read file content using the opened file descriptor
        with os.fdopen(fd, 'rb') as f:
            content = f.read(MAX_FILE_SIZE + 1)

            # Additional runtime check against size limit
            if len(content) > MAX_FILE_SIZE:
                raise PermissionError("File size exceeds limit during read")

            return content
    except Exception:
        # Ensure fd is closed if fdopen wasn't successful
        if fd >= 0:
            try:
                os.close(fd)
            except Exception:
                pass
        raise

if __name__ == '__main__':
    # Create test files
    (BASE_DIR / "test1.txt").write_bytes(b"Test file 1")
    (BASE_DIR / "test2.jpg").write_bytes(b"Image data")
    (BASE_DIR / "safe.png").write_bytes(b"Safe image")
    
    # Test case 1: Valid file
    try:
        content = img("test1.txt")
        print(f"Test 1 passed: {content.decode()}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Another valid file
    try:
        content = img("test2.jpg")
        print(f"Test 2 passed: {content.decode()}")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: Path traversal attempt (should fail)
    try:
        content = img("../etc/passwd")
        print("Test 3 FAILED: Path traversal succeeded")
    except PermissionError:
        print("Test 3 passed: Path traversal blocked")
    
    # Test case 4: Empty input (should fail)
    try:
        content = img("")
        print("Test 4 FAILED: Empty string accepted")
    except ValueError:
        print("Test 4 passed: Empty string rejected")
    
    # Test case 5: Non-existent file (should fail)
    try:
        content = img("nonexistent.txt")
        print("Test 5 FAILED: Non-existent file returned data")
    except FileNotFoundError:
        print("Test 5 passed: Non-existent file handled")
    
    print("\\nStarting Flask server on port 5000...")
    app.run(host='127.0.0.1', port=5000, debug=False)
