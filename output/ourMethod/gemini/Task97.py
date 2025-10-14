import sys
import os
import re
import xml.etree.ElementTree as ET
from typing import List

# Rule #1: Regex for validating the ID to be alphanumeric + underscore
ID_PATTERN = re.compile(r"^[a-zA-Z0-9_]+$")

def execute_xpath_query(id_val: str, filename: str) -> List[str]:
    """
    Executes an XPath query to find nodes by ID.

    Args:
        id_val: The ID to search for. Must be a simple alphanumeric string.
        filename: The path to the XML file. Must be a simple filename without path components.

    Returns:
        A list of string contents of the found nodes.
    
    Raises:
        ValueError: For invalid inputs.
        FileNotFoundError: If the file does not exist.
        ET.ParseError: If the XML is malformed.
    """
    # Rule #1: Validate ID input
    if not ID_PATTERN.match(id_val):
        raise ValueError("Invalid ID format. Only alphanumeric characters and underscores are allowed.")

    # Rule #5: Validate filename to prevent path traversal
    if filename is None or os.path.basename(filename) != filename or not os.path.exists(filename) or not os.path.isfile(filename):
        raise ValueError("Invalid file path. It must be a simple, existing filename in the current directory.")

    try:
        # Rule #4: The default parser in xml.etree.ElementTree is secure against XXE
        tree = ET.parse(filename)
        root = tree.getroot()
        
        # The format is /tag[@id={}], here we use `*` for any tag.
        # findall supports a subset of XPath. This format is supported.
        # ID is validated, so string formatting is safe here.
        query = f".//*[@id='{id_val}']"
        
        results = []
        for node in root.findall(query):
            if node.text:
                results.append(node.text)
        return results
    except ET.ParseError as e:
        raise ValueError(f"Error parsing XML file: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filename}")


def setup_test_file(filename: str):
    """Creates a sample XML file for testing."""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<root>
    <item id="item1">Content 1</item>
    <data>
        <item id="item2">Content 2</item>
    </data>
    <item id="item3">Content 3</item>
    <item id="another_id_4">More Content</item>
</root>"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(xml_content)

def cleanup_test_file(filename: str):
    """Removes the sample XML file."""
    if os.path.exists(filename):
        os.remove(filename)

def main():
    """Main function to handle command-line arguments or run test cases."""
    if len(sys.argv) != 3:
        print("Usage: python your_script.py <id> <xml_file>", file=sys.stderr)
        print("Running test cases instead...", file=sys.stderr)
        run_tests()
        return

    id_val = sys.argv[1]
    filename = sys.argv[2]
    
    try:
        results = execute_xpath_query(id_val, filename)
        print("Query Result:")
        if not results:
            print("No nodes found.")
        else:
            for res in results:
                print(res)
    except (ValueError, FileNotFoundError) as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)


def run_tests():
    """Runs a series of test cases."""
    test_file = "test97.xml"
    setup_test_file(test_file)
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Valid ID, existing item
    print(f"\n[Test 1] ID: 'item1', File: '{test_file}'")
    try:
        print(f"Result: {execute_xpath_query('item1', test_file)}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    # Test Case 2: Valid ID, nested item
    print(f"\n[Test 2] ID: 'item2', File: '{test_file}'")
    try:
        print(f"Result: {execute_xpath_query('item2', test_file)}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    # Test Case 3: Valid ID, non-existent item
    print(f"\n[Test 3] ID: 'nonexistent', File: '{test_file}'")
    try:
        print(f"Result: {execute_xpath_query('nonexistent', test_file)}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    # Test Case 4: Invalid ID (potential injection)
    print(f"\n[Test 4] ID: \"' or '1'='1'\", File: '{test_file}'")
    try:
        execute_xpath_query("' or '1'='1'", test_file)
    except Exception as e:
        print(f"Caught expected error: {e}", file=sys.stderr)

    # Test Case 5: Invalid filename (path traversal)
    print(f"\n[Test 5] ID: 'item1', File: '../test97.xml'")
    try:
        execute_xpath_query('item1', '../test97.xml')
    except Exception as e:
        print(f"Caught expected error: {e}", file=sys.stderr)
    
    print("\n--- Test Cases Finished ---")
    cleanup_test_file(test_file)

if __name__ == "__main__":
    main()