
import os
import secrets
import tempfile
from pathlib import Path

# Maximum file size limit
MAX_FILE_SIZE = 1024 * 1024  # 1MB
def generate_and_write_random_floats(filename: str, base_dir: str = None) -> bool:
    """
    Generates 3 random floats, converts to strings, concatenates them,
    and writes to a file securely.

    Args:
        filename: Target filename (must be relative path without traversal)
        base_dir: Base directory (defaults to current directory)

    Returns:
        True if successful, False otherwise
    """
    if not filename or not isinstance(filename, str):
        print("Invalid filename", flush=True)
        return False

    # Validate filename - reject path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        print("Invalid filename: path traversal detected", flush=True)
        return False

    try:
        # Set base directory
        if base_dir is None:
            base_dir = os.getcwd()

        base_path = Path(base_dir).resolve()

        # Generate 3 random floats using secrets (cryptographically secure)
        float1 = secrets.SystemRandom().random()
        float2 = secrets.SystemRandom().random()
        float3 = secrets.SystemRandom().random()

        # Convert to strings and concatenate
        concatenated = str(float1) + str(float2) + str(float3)

        # Encode to bytes for size validation
        data = concatenated.encode('utf-8')
        if len(data) > MAX_FILE_SIZE:
            print("Data exceeds maximum file size", flush=True)
            return False

        # Resolve target path and ensure it's within base directory
        target_path = (base_path / filename).resolve()
        if not str(target_path).startswith(str(base_path)):
            print("Path resolves outside base directory", flush=True)
            return False

        # Create temp file in same directory with restrictive permissions
        # Using os.open for better control and security
        fd = None
        temp_path = None

        try:
            # Create temp file descriptor with restrictive permissions (0o600)
            fd = os.open(
                str(base_path / f"temp_{secrets.token_hex(8)}.tmp"),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                )
            temp_path = base_path / f"temp_{secrets.token_hex(8)}.tmp"

            # Get the actual temp file path
            temp_path = Path(f"/dev/fd/{fd}").resolve() if os.name != 'nt' else None
            if temp_path is None or os.name == 'nt':
                # Fallback for systems without /dev/fd or Windows
                os.close(fd)
                fd = None
                with tempfile.NamedTemporaryFile(
                        mode='wb',
                        dir=str(base_path),
                        delete=False,
                        prefix='temp_',
                        suffix='.tmp',
                ) as tf:
                    temp_path = Path(tf.name)
                    tf.write(data)
                    tf.flush()
                    os.fsync(tf.fileno())
            else:
                # Write using file descriptor
                with os.fdopen(fd, 'wb') as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                fd = None  # fdopen takes ownership

            # Atomic replace
            os.replace(str(temp_path), str(target_path))
            return True

        except Exception:
            # Clean up temp file on error
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    pass
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            raise

    except Exception:
        print("Operation failed", flush=True)
        return False

def main():
    # Test case 1: Valid filename
    print(f"Test 1: {generate_and_write_random_floats('output1.txt')}")
    
    # Test case 2: Another valid filename
    print(f"Test 2: {generate_and_write_random_floats('output2.txt')}")
    
    # Test case 3: Valid filename
    print(f"Test 3: {generate_and_write_random_floats('result.txt')}")
    
    # Test case 4: Invalid - path traversal attempt
    print(f"Test 4: {generate_and_write_random_floats('../output.txt')}")
    
    # Test case 5: Invalid - empty filename
    print(f"Test 5: {generate_and_write_random_floats('')}")

if __name__ == "__main__":
    main()
