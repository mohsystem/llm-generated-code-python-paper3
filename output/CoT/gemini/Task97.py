import sys
import os
from lxml import etree

def execute_xpath(xml_file_path, xpath_expression):
    """
    Executes an XPath query on a given XML file.

    :param xml_file_path: The path to the XML file.
    :param xpath_expression: The XPath expression to execute.
    :return: A list of strings representing the query result.
    """
    results = []
    if not os.path.exists(xml_file_path):
        print(f"Error: XML file not found at {xml_file_path}", file=sys.stderr)
        return results
        
    try:
        # Secure parsing: resolve_entities=False prevents XXE attacks
        parser = etree.XMLParser(resolve_entities=False)
        tree = etree.parse(xml_file_path, parser)
        query_results = tree.xpath(xpath_expression)
        
        for item in query_results:
            if isinstance(item, etree._Element):
                results.append(item.text)
            else:
                results.append(str(item))
                
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        
    return results

# Main execution block with 5 test cases
if __name__ == '__main__':
    # Create a dummy XML file for testing
    xml_file_name = "test97.xml"
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
  <book id="1">
    <title lang="en">Harry Potter</title>
    <author>J. K. Rowling</author>
  </book>
  <book id="2">
    <title lang="en">Learning XML</title>
    <author>Erik T. Ray</author>
  </book>
  <novel id="3">
    <title lang="en">The Great Gatsby</title>
    <author>F. Scott Fitzgerald</author>
  </novel>
</bookstore>
"""
    with open(xml_file_name, "w") as f:
        f.write(xml_content)

    # Simulating command line arguments: xpath, filename
    test_cases = [
        ("/bookstore/book/title", xml_file_name),  # Test Case 1: Get all book titles
        ("/bookstore/book[@id='1']/title", xml_file_name),  # Test Case 2: Get title of book with id=1
        ("//author", xml_file_name),  # Test Case 3: Get all authors
        ("/bookstore/novel/title", xml_file_name), # Test Case 4: Get novel titles
        ("/bookstore/book[@id='99']/title", xml_file_name)  # Test Case 5: Query for non-existent node
    ]

    for i, (xpath, filename) in enumerate(test_cases):
        print(f"--- Test Case {i + 1} ---")
        print(f"Executing XPath: {xpath} on {filename}")
        
        results = execute_xpath(filename, xpath)
        
        print(f"Result: {results}")
        print()
    
    # Clean up the dummy file
    os.remove(xml_file_name)