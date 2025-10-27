import sys

DATA = [100, 200, 300, 400, 500]

def print_element_at_index(args):
    """
    Parses an index from args, validates it, and prints the element from DATA.
    Args:
        args: A list of command-line arguments, including the script name.
    """
    # sys.argv includes the script name, so we expect 2 elements.
    if len(args) != 2:
        print("Usage: python3 <script_name> <index>", file=sys.stderr)
        return

    index_str = args[1]
    try:
        index = int(index_str)
        
        # Explicitly check if the index is within the valid bounds.
        if 0 <= index < len(DATA):
            print(f"Element at index {index}: {DATA[index]}")
        else:
            print(f"Error: Index {index} is out of bounds. Valid range is 0 to {len(DATA) - 1}.", file=sys.stderr)
            
    except ValueError:
        print(f"Error: Argument '{index_str}' must be a valid integer.", file=sys.stderr)

def main():
    """ Main entry point and test runner """
    # This block allows the script to be run with actual command-line arguments.
    if len(sys.argv) > 1:
        print("--- Running with actual command-line arguments ---")
        print_element_at_index(sys.argv)
        print("-----------------------------------------------\n")

    # Running 5 test cases as requested.
    print("--- Running 5 built-in test cases ---")

    print("\n[Test 1] Valid index '2':")
    # Simulate sys.argv, which includes the script name as the first element.
    print_element_at_index(["your_script.py", "2"])

    print("\n[Test 2] Out of bounds index '10':")
    print_element_at_index(["your_script.py", "10"])
    
    print("\n[Test 3] Negative index '-1':")
    print_element_at_index(["your_script.py", "-1"])

    print("\n[Test 4] Non-numeric input 'abc':")
    print_element_at_index(["your_script.py", "abc"])

    print("\n[Test 5] No arguments:")
    print_element_at_index(["your_script.py"])
    
    print("\n--- Test cases finished ---")

if __name__ == "__main__":
    main()