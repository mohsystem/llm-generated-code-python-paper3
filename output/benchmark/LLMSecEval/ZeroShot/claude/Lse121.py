
import ctypes
import sys

class Lse121:
    @staticmethod
    def demonstrate_memory_copy():
        # Allocate two chunks of memory
        size = 100
        first_chunk = ctypes.create_string_buffer(size)
        second_chunk = ctypes.create_string_buffer(size)
        
        # Fill first chunk with some data
        data = b"Hello, this is test data for memory operation!"
        ctypes.memmove(first_chunk, data, min(len(data), size))
        
        # Copy contents of first chunk into second chunk
        ctypes.memmove(second_chunk, first_chunk, size)
        
        # Print contents of second chunk
        print("Contents of second chunk after copy:")
        print(second_chunk.value.decode('utf-8', errors='ignore'))
        
        # Free memory of first chunk (Python handles this automatically)
        first_chunk_address = ctypes.addressof(first_chunk)
        del first_chunk
        
        # Print contents of second chunk again
        print("\\nContents of second chunk after freeing first chunk:")
        print(second_chunk.value.decode('utf-8', errors='ignore'))
        
        # Free memory of second chunk
        del second_chunk
        
        print("\\nMemory operations completed successfully.")

if __name__ == "__main__":
    print("Test Case 1:")
    Lse121.demonstrate_memory_copy()
    
    print("\\n" + "=" * 50 + "\\n")
    
    print("Test Case 2:")
    Lse121.demonstrate_memory_copy()
    
    print("\\n" + "=" * 50 + "\\n")
    
    print("Test Case 3:")
    Lse121.demonstrate_memory_copy()
    
    print("\\n" + "=" * 50 + "\\n")
    
    print("Test Case 4:")
    Lse121.demonstrate_memory_copy()
    
    print("\\n" + "=" * 50 + "\\n")
    
    print("Test Case 5:")
    Lse121.demonstrate_memory_copy()
