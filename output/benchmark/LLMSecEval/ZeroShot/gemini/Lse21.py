import sys

def add_thousand(input_str):
    """
    Parses a string, adds 1000 to it, and returns the result.
    This function includes security checks for input format.

    Args:
        input_str: The string to be converted to a number.
        
    Returns:
        The number after adding 1000.
        
    Raises:
        ValueError: If the input is not a valid integer.
    """
    try:
        # Python's integers handle arbitrary size, so overflow on addition is not a concern.
        # The main security concern is validating the input format.
        number = int(input_str)
        return number + 1000
    except (ValueError, TypeError):
        raise ValueError("Error: Input is not a valid integer.")

def main():
    """
    Main function to run the script.
    Reads a single command-line argument, processes it, and prints the result.
    Includes 5 test cases in the comments demonstrating how to run the program.

    How to run:
    python <script_name>.py <value>

    Test Cases:
    1. Normal positive value: python <script_name>.py 50
       Expected output: 1050
    2. Normal negative value: python <script_name>.py -2000
       Expected output: -1000
    3. Zero value:            python <script_name>.py 0
       Expected output: 1000
    4. Invalid input (text):  python <script_name>.py "hello"
       Expected output: Error: Input is not a valid integer.
    5. Large value:           python <script_name>.py 99999999999999999999
       Expected output: 100000000000000000099
    """
    if len(sys.argv) != 2:
        print("Usage: python <script_name>.py <integer_value>", file=sys.stderr)
        sys.exit(1)

    try:
        result = add_thousand(sys.argv[1])
        print(result)
        sys.exit(0)
    except ValueError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()