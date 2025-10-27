
import sys

def main():
    try:
        # Validate that we have at least 2 arguments (script name + 2 args)
        if len(sys.argv) < 3:
            print("Error: Insufficient arguments", file=sys.stderr)
            return
        
        # Validate the index argument is not empty
        if not sys.argv[2] or not sys.argv[2].strip():
            print("Error: Invalid index", file=sys.stderr)
            return
        
        try:
            # Convert string to integer with validation
            index = int(sys.argv[2].strip())
        except ValueError:
            print("Error: Invalid number format", file=sys.stderr)
            return
        
        # Validate index is within valid range [0, len(sys.argv)-1]
        # Prevent negative index and out of bounds access
        if index < 0 or index >= len(sys.argv):
            print("Error: Index out of bounds", file=sys.stderr)
            return
        
        # Safely print the argument at the validated index
        print(sys.argv[index])
        
    except Exception:
        # Catch any unexpected exceptions, log generically
        print("Error: Operation failed", file=sys.stderr)

if __name__ == "__main__":
    main()
