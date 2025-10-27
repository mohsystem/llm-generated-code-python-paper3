from typing import Union

def safe_copy_bytes(dest: bytearray, src: Union[bytes, bytearray], n: int) -> int:
    """
    Copies a number of bytes from src to dest.
    First argument: destination buffer (bytearray)
    Second argument: source buffer (bytes or bytearray)
    Third argument: number of bytes to copy
    Returns: number of bytes actually copied (bounded by dest and src sizes).
    """
    if not isinstance(dest, bytearray):
        return 0
    if not isinstance(src, (bytes, bytearray)):
        return 0
    if not isinstance(n, int) or n <= 0:
        return 0
    to_copy = min(n, len(dest), len(src))
    if to_copy <= 0:
        return 0
    dest[0:to_copy] = src[0:to_copy]
    return to_copy

def _print_result(label: str, buf: bytearray, copied: int) -> None:
    content = buf[:copied].decode('utf-8', errors='ignore')
    print(f"{label} bytes_copied={copied}, content='{content}'")

if __name__ == "__main__":
    # Test 1: Copy full message to sufficiently large buffer
    message1 = "Hello, Secure World!".encode("utf-8")
    buffer1 = bytearray(64)
    copied1 = safe_copy_bytes(buffer1, message1, len(message1))
    _print_result("Test 1", buffer1, copied1)

    # Test 2: Partial copy
    message2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".encode("utf-8")
    buffer2 = bytearray(32)
    copied2 = safe_copy_bytes(buffer2, message2, 5)
    _print_result("Test 2", buffer2, copied2)

    # Test 3: n larger than destination capacity
    message3 = "1234567890abcdefghijklmnop".encode("utf-8")
    buffer3 = bytearray(10)
    copied3 = safe_copy_bytes(buffer3, message3, 50)
    _print_result("Test 3", buffer3, copied3)

    # Test 4: Zero-length copy
    message4 = "NoCopy".encode("utf-8")
    buffer4 = bytearray(10)
    copied4 = safe_copy_bytes(buffer4, message4, 0)
    _print_result("Test 4", buffer4, copied4)

    # Test 5: Empty source
    message5 = b""
    buffer5 = bytearray(10)
    copied5 = safe_copy_bytes(buffer5, message5, 5)
    _print_result("Test 5", buffer5, copied5)