import os
import sys
import time

def read_and_write_file(source_file_path, temp_directory):
    reader = None
    writer = None
    temp_file_path = None

    try:
        # Validate input parameters
        if source_file_path is None or not source_file_path.strip():
            raise ValueError("Source file path cannot be None or empty")
        if temp_directory is None or not temp_directory.strip():
            raise ValueError("Temp directory cannot be None or empty")

        # Check if source file exists
        if not os.path.exists(source_file_path):
            raise FileNotFoundError(f"Source file does not exist: {source_file_path}")
        if not os.path.isfile(source_file_path):
            raise ValueError(f"Source path is not a file: {source_file_path}")
        if not os.access(source_file_path, os.R_OK):
            raise IOError(f"Cannot read source file: {source_file_path}")

        # Create temp directory if it doesn't exist
        if not os.path.exists(temp_directory):
            try:
                os.makedirs(temp_directory)
            except OSError as e:
                raise IOError(f"Failed to create temp directory: {temp_directory}") from e

        # Create temp file
        file_name = os.path.basename(source_file_path)
        temp_file_path = os.path.join(
            temp_directory,
            f"temp_{int(time.time() * 1000)}_{file_name}"
        )

        # Read from source and write to temp
        with open(source_file_path, 'r', encoding='utf-8') as reader:
            with open(temp_file_path, 'w', encoding='utf-8') as writer:
                for line in reader:
                    writer.write(line)

        return temp_file_path

    except FileNotFoundError as e:
        print(f"File not found error: {e}", file=sys.stderr)
        return None
    except IOError as e:
        print(f"IO error: {e}", file=sys.stderr)
        return None
    except ValueError as e:
        print(f"Invalid argument: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return None


def main():
    print("Testing File Read and Write with Exception Handling\n")

    # Test Case 1: Valid file and temp directory
    print("Test Case 1: Valid file and temp directory")
    try:
        with open("test1.txt", 'w') as f:
            f.write("Hello World!\nThis is test file 1.")

        result = read_and_write_file("test1.txt", "./temp")
        print(f"Result: {'Success - ' + result if result else 'Failed'}")
        if os.path.exists("test1.txt"):
            os.remove("test1.txt")
    except Exception as e:
        print(f"Setup error: {e}")
    print()

    # Test Case 2: Non-existent source file
    print("Test Case 2: Non-existent source file")
    result2 = read_and_write_file("nonexistent.txt", "./temp")
    print(f"Result: {'Success - ' + result2 if result2 else 'Failed (Expected)'}")
    print()

    # Test Case 3: None source file path
    print("Test Case 3: None source file path")
    result3 = read_and_write_file(None, "./temp")
    print(f"Result: {'Success - ' + result3 if result3 else 'Failed (Expected)'}")
    print()

    # Test Case 4: Empty source file path
    print("Test Case 4: Empty source file path")
    result4 = read_and_write_file("", "./temp")
    print(f"Result: {'Success - ' + result4 if result4 else 'Failed (Expected)'}")
    print()

    # Test Case 5: Valid file with special characters
    print("Test Case 5: Valid file with special characters")
    try:
        with open("test5.txt", 'w', encoding='utf-8') as f:
            f.write("Special chars: @#$%^&*()\nUnicode: \u00A9 \u00AE")

        result5 = read_and_write_file("test5.txt", "./temp")
        print(f"Result: {'Success - ' + result5 if result5 else 'Failed'}")
        if os.path.exists("test5.txt"):
            os.remove("test5.txt")
    except Exception as e:
        print(f"Setup error: {e}")
    print()

    # Cleanup
    try:
        if os.path.exists("./temp"):
            for file in os.listdir("./temp"):
                os.remove(os.path.join("./temp", file))
            os.rmdir("./temp")
    except Exception as e:
        print(f"Cleanup error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
