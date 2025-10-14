import csv
import io
import os
import tempfile
from typing import List

def parse_csv_content(content: str) -> List[List[str]]:
    """
    Parses CSV content from a string using Python's built-in csv module.

    Args:
        content: A string containing CSV data.

    Returns:
        A list of lists, where each inner list is a row.
    Raises:
        TypeError: If input content is not a string.
    """
    if not isinstance(content, str):
        raise TypeError("Input content must be a string.")
    
    # Use io.StringIO to treat the string as a file for the csv module
    f = io.StringIO(content)
    # Using the default 'excel' dialect which handles quoted fields, newlines etc.
    reader = csv.reader(f)
    try:
        return [row for row in reader]
    except csv.Error as e:
        print(f"Error parsing CSV content: {e}")
        return []

def read_and_parse_csv(file_path: str) -> List[List[str]]:
    """
    Reads a CSV file securely and parses its content.

    Args:
        file_path: The path to the CSV file.

    Returns:
        A list of lists representing the CSV data.
    
    Raises:
        PermissionError: If path traversal or non-relative path is detected.
        FileNotFoundError: If the file does not exist.
        IOError: For other I/O related errors.
    """
    if ".." in file_path or os.path.isabs(file_path):
        raise PermissionError("Path traversal or absolute path detected. Only relative paths are allowed.")

    # Securely join with a safe base directory (current working directory)
    safe_base_dir = os.path.abspath(".")
    resolved_path = os.path.abspath(os.path.join(safe_base_dir, file_path))

    if not resolved_path.startswith(safe_base_dir):
        raise PermissionError("Path resolves outside the allowed base directory.")

    if not os.path.isfile(resolved_path):
         raise FileNotFoundError(f"File not found or is not a regular file: {resolved_path}")

    records = []
    try:
        # Use a context manager for safe file handling
        with open(resolved_path, mode='r', newline='', encoding='utf-8') as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            for row in csv_reader:
                records.append(row)
    except (IOError, csv.Error) as e:
        print(f"Error processing file {resolved_path}: {e}")
        raise
    return records

def main():
    """Main function with test cases."""
    test_csv_data = [
        "a,b,c\n1,2,3",
        'a,"b,c",d\n1,"2,3",4',
        'a,"b""c",d\n1,"2""3",4',
        "a,,c\n1,2,",
        'header1,header2\n"field with\nnew line",field2',
    ]

    for i, data in enumerate(test_csv_data):
        test_filename = f"test_{i+1}.csv"
        try:
            with open(test_filename, "w", encoding='utf-8', newline='') as f:
                f.write(data)

            print(f"--- Test Case {i + 1} ---")
            print(f"Input CSV:\n{data}")
            
            try:
                # Test the file reading function
                result_from_file = read_and_parse_csv(test_filename)
                print("Parsed Output (from file):")
                for row in result_from_file:
                    print(f"  {row}")

            except (PermissionError, FileNotFoundError, IOError, csv.Error) as e:
                print(f"File parsing test failed: {e}")

            # Test the content parsing function
            result_from_string = parse_csv_content(data)
            print("Parsed Output (from string):")
            for row in result_from_string:
                print(f"  {row}")

            print()

        except IOError as e:
            print(f"Test case setup failed for test {i+1}: {e}")
        finally:
            if os.path.exists(test_filename):
                os.remove(test_filename)

if __name__ == "__main__":
    main()