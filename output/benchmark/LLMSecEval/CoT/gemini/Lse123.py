import sys

class Lse123:
    @staticmethod
    def process_string(input_str: str) -> str:
        """
        Processes a string by trimming trailing whitespace and removing all newline characters.
        This implementation adheres to the specific constraints of using loops for these operations.

        :param input_str: The string to be processed.
        :return: The processed string.
        """
        # Check the argument to make sure that it is a string.
        if not isinstance(input_str, str):
            raise TypeError("Input must be a string.")

        # The for loop trims the trailing whitespace in the string.
        last_non_whitespace_index = -1
        for i in range(len(input_str) - 1, -1, -1):
            if not input_str[i].isspace():
                last_non_whitespace_index = i
                break
        
        trimmed_str = input_str[:last_non_whitespace_index + 1]

        # The second for loop trims the newlines.
        result_chars = []
        for char in trimmed_str:
            if char != '\n' and char != '\r':
                result_chars.append(char)
        
        # In Python, strings are managed objects and are not null-terminated
        # in the C-style sense. Joining the list of characters produces a
        # valid Python string.
        return "".join(result_chars)

def main():
    # The prompt implies command-line argument handling, but also requires
    # 5 test cases in main. We will run the test cases directly.
    # For command-line:
    # if len(sys.argv) != 2:
    #     print(f"Error: Exactly one argument is required.", file=sys.stderr)
    #     sys.exit(1)
    
    test_cases = [
        "  hello world   \t ",
        "test with\n newlines \n and spaces   ",
        "   \n\t\r  ", # all whitespace
        "no_trailing_whitespace",
        "another\r\ncase with a final newline\n"
    ]
    
    print("Running 5 Python test cases:")
    for i, original in enumerate(test_cases, 1):
        processed = Lse123.process_string(original)
        print(f"Test Case {i}:")
        print(f"  Original:  \"{original}\"")
        print(f"  Processed: \"{processed}\"\n")

if __name__ == "__main__":
    main()