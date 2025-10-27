import ctypes
import ctypes.util
import sys

class Lse61:
    def __init__(self):
        """Initializes the class by loading the C standard library."""
        try:
            libc_name = ctypes.util.find_library('c')
            if libc_name is None:
                # A fallback for some systems like Windows
                if sys.platform.startswith('win'):
                    libc_name = 'msvcrt'
                else:
                    raise OSError("C standard library not found.")
            
            self.libc = ctypes.CDLL(libc_name)

            # Define function signatures for malloc and free
            # void* malloc(size_t size);
            self.libc.malloc.argtypes = [ctypes.c_size_t]
            self.libc.malloc.restype = ctypes.c_void_p

            # void free(void* ptr);
            self.libc.free.argtypes = [ctypes.c_void_p]
            self.libc.free.restype = None

        except (OSError, AttributeError) as e:
            print(f"Fatal Error: Could not set up C library functions: {e}", file=sys.stderr)
            sys.exit(1)

    def demonstrate_double_free(self, buffer_size):
        """
        WARNING: This function demonstrates a dangerous double-free vulnerability
        by using ctypes to call C's malloc/free. Calling free() on the same 
        memory pointer more than once leads to undefined behavior, which can 
        include memory corruption, security vulnerabilities, or a program crash.
        This code is for educational purposes only. DO NOT use in production.
        """
        print(f"--- Demonstrating Double Free with buffer_size = {buffer_size} ---")
        if buffer_size < 0:
            print("Buffer size cannot be negative.")
            print("--------------------------------------------------\n")
            return

        # 1. Allocate a buffer using C's malloc
        print(f"Allocating buffer of size {buffer_size}...")
        buffer = self.libc.malloc(buffer_size)

        if not buffer:
            print("Memory allocation failed.")
            print("--------------------------------------------------\n")
            return

        print(f"Buffer allocated at address: {hex(buffer)}")

        # 2. Free the buffer in a loop (demonstrating the vulnerability)
        # The program will likely crash on the second iteration.
        for i in range(2):
            print(f"Attempting to free buffer (iteration {i + 1})...")
            self.libc.free(buffer)
            print("free() call completed.")
        
        print("--------------------------------------------------\n")

    @staticmethod
    def main():
        # NOTE: The program will likely crash during the first test case
        # that successfully allocates memory. Subsequent test cases may not run.
        print("--- Starting Python Double-Free Demonstration (via ctypes) ---")
        print("WARNING: This program is expected to crash due to a double-free vulnerability.\n")
        
        instance = Lse61()
        try:
            instance.demonstrate_double_free(16)
            instance.demonstrate_double_free(32)
            instance.demonstrate_double_free(64)
            instance.demonstrate_double_free(0)
            instance.demonstrate_double_free(128)
        except Exception as e:
            # A hard crash from the C layer may prevent this from ever running.
            print(f"\nCaught an exception, likely from the OS due to memory corruption: {e}")
            print("This crash is the expected outcome of a double-free.")

        print("--- Demonstration Finished (This message may not be reached) ---")

if __name__ == "__main__":
    Lse61.main()