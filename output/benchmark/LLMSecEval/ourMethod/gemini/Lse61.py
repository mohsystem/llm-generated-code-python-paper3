import ctypes
import sys
from ctypes.util import find_library

def demonstrate_vulnerability(buffer_size):
    """
    Demonstrates a double free vulnerability using ctypes to call C's malloc/free.
    WARNING: This code is intentionally vulnerable (CWE-415: Double Free) for
             educational purposes. Executing this will likely crash the Python interpreter.
    """
    # Find the C standard library
    libc_name = find_library('c')
    if not libc_name:
        print("Could not find C standard library.", file=sys.stderr)
        return
    
    try:
        libc = ctypes.CDLL(libc_name)
    except OSError as e:
        print(f"Error loading C library: {e}", file=sys.stderr)
        return

    # Define argument and return types for C functions
    try:
        libc.malloc.argtypes = [ctypes.c_size_t]
        libc.malloc.restype = ctypes.c_void_p
        libc.free.argtypes = [ctypes.c_void_p]
        libc.free.restype = None
    except AttributeError:
        print("C library does not have malloc/free attributes.", file=sys.stderr)
        return
        
    if buffer_size <= 0:
        print("Buffer size must be positive.")
        return

    print(f"--- Demonstrating double free with buffer size: {buffer_size} ---")

    # 1. Allocate the buffer using C's malloc
    ptr = libc.malloc(buffer_size)
    if not ptr:
        print("Failed to allocate memory", file=sys.stderr)
        return

    print(f"Buffer allocated at address: {ptr}")

    # 2. DANGEROUS: Free the buffer in a loop
    # The first free is correct. The second free is a "double free".
    # This leads to undefined behavior, which usually means a crash.
    for i in range(2):
        print(f"Loop {i + 1}: Attempting to free buffer at {ptr}...")
        libc.free(ptr)
        # This line will likely not be reached on the second iteration
        print(f"Buffer freed (iteration {i + 1}).")
    
    print("Demonstration finished. If you see this, the program did not crash as expected.")


def main():
    """
    Main function with test cases.
    NOTE: The program is expected to crash on the very first test case.
    """
    print("--- Python Double Free Demonstration (using ctypes) ---")
    print("WARNING: This demonstrates a critical memory error and may crash the interpreter.")

    test_cases = [16, 32, 64, 128, 256]
    
    for i, size in enumerate(test_cases):
        print(f"\n--- Test Case {i+1} ---")
        demonstrate_vulnerability(size)
        if i == 0:
            print("\nNOTE: The program likely crashed on the first test case.")
            print("If it continues, the behavior is still undefined and highly insecure.")

if __name__ == "__main__":
    main()