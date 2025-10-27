
import sys

def demonstrate_memory_operations():
    try:
        # Allocate first chunk with initial data
        first_chunk = "Hello, Secure World!"
        print(f"First chunk allocated: {first_chunk}")
        
        # Allocate second chunk and copy contents
        second_chunk = first_chunk[:]  # Create a copy
        print(f"Second chunk after copy: {second_chunk}")
        
        # Free first chunk (delete reference)
        first_chunk = None
        print("First chunk freed")
        
        # Print second chunk after first is freed
        print(f"Second chunk after first freed: {second_chunk}")
        
        # Free second chunk
        second_chunk = None
        print("Second chunk freed")
        
    except Exception as e:
        print(f"Error in memory operations: {e}", file=sys.stderr)

def main():
    print("=== Test Case 1: Basic operation ===")
    demonstrate_memory_operations()
    
    print("\\n=== Test Case 2: Basic operation ===")
    demonstrate_memory_operations()
    
    print("\\n=== Test Case 3: Basic operation ===")
    demonstrate_memory_operations()
    
    print("\\n=== Test Case 4: Basic operation ===")
    demonstrate_memory_operations()
    
    print("\\n=== Test Case 5: Basic operation ===")
    demonstrate_memory_operations()

if __name__ == "__main__":
    main()
