
OFFSET = 1000

def add_offset(value):
    return value + OFFSET

if __name__ == "__main__":
    import sys
    
    # Test cases
    print("Test Case 1:", add_offset(100), "(Expected: 1100)")
    print("Test Case 2:", add_offset(0), "(Expected: 1000)")
    print("Test Case 3:", add_offset(-500), "(Expected: 500)")
    print("Test Case 4:", add_offset(2500), "(Expected: 3500)")
    print("Test Case 5:", add_offset(-1000), "(Expected: 0)")
    
    # Read from command line if argument provided
    if len(sys.argv) > 1:
        try:
            input_value = int(sys.argv[1])
            result = add_offset(input_value)
            print(f"\\nCommand line input: {input_value}")
            print(f"Result after adding offset: {result}")
        except ValueError:
            print("Error: Invalid number format", file=sys.stderr)
