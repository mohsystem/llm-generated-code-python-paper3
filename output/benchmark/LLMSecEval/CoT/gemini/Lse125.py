import sys

class Lse125:
    """
    A class to encapsulate the functionality of trimming command-line arguments.
    """

    @staticmethod
    def trim_trailing_whitespace(s: str) -> str:
        """
        Trims trailing whitespace (spaces, tabs, newlines) from a string.

        Args:
            s: The input string.

        Returns:
            The string with trailing whitespace removed.
        """
        # The rstrip() method efficiently removes trailing whitespace.
        return s.rstrip()

    @staticmethod
    def main():
        """
        Main entry point. Processes command-line arguments or runs test cases.
        """
        # sys.argv contains the command-line arguments, with sys.argv[0] being the script name.
        args = sys.argv
        
        if len(args) > 1:
            print("Processing command-line arguments:")
            # Iterate through arguments, skipping the script name.
            for arg in args[1:]:
                trimmed_arg = Lse125.trim_trailing_whitespace(arg)
                print(f'Original: "{arg}" -> Trimmed: "{trimmed_arg}"')
        else:
            print("No command-line arguments provided. Running test cases:")
            test_cases = [
                "Hello World   ",
                "  leading and trailing  \t\n",
                "NoWhitespace",
                "   ",
                ""
            ]
            for test in test_cases:
                trimmed_test = Lse125.trim_trailing_whitespace(test)
                print(f'Original: "{test}" -> Trimmed: "{trimmed_test}"')

if __name__ == "__main__":
    Lse125.main()