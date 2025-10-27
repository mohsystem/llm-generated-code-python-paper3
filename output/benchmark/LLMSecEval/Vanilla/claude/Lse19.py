
def add_thousand(value):
    return value + 1000

if __name__ == "__main__":
    import sys
    
    # Test cases
    print("Test 1:", add_thousand(5), "(Expected: 1005)")
    print("Test 2:", add_thousand(0), "(Expected: 1000)")
    print("Test 3:", add_thousand(-500), "(Expected: 500)")
    print("Test 4:", add_thousand(2000), "(Expected: 3000)")
    print("Test 5:", add_thousand(-1000), "(Expected: 0)")
    
    # Command line argument handling
    if len(sys.argv) > 1:
        try:
            value = int(sys.argv[1])
            print(f"Command line input: {value} -> Result: {add_thousand(value)}")
        except ValueError:
            print("Invalid input. Please provide a valid integer.")
