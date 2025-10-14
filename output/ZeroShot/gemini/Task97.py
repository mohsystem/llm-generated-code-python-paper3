# lxml library is required. Install it using: pip install lxml
import os
from lxml import etree

def perform_xpath_query(id_val, filename):
    """
    Executes a secure XPath query on a local XML file.

    :param id_val: The ID value to be used in the XPath query.
    :param filename: The name of the XML file to query.
    :return: The text content of the first matching node, or "Not found".
    """
    # 1. Secure Filename Handling: Prevent path traversal by only using the basename
    base_filename = os.path.basename(filename)
    if not os.path.exists(base_filename):
        return "Error: File not found."

    try:
        # 2. Secure XML Parsing: Disable entity resolution to prevent XXE attacks
        parser = etree.XMLParser(resolve_entities=False)
        tree = etree.parse(base_filename, parser)

        # 3. Secure XPath Execution: Use parameterized query to prevent XPath injection
        # The query uses a variable ($id_param) instead of formatting the user input directly
        expression = "//tag[@id=$id_param]"
        
        # The id_val is passed as a parameter, not as part of the string
        results = tree.xpath(expression, id_param=id_val)

        if results:
            return results[0].text
        else:
            return "Not found"
            
    except etree.XMLSyntaxError as e:
        return f"Error: Malformed XML - {e}"
    except Exception as e:
        return f"Error: {e}"

def main():
    # Create a dummy XML file for testing
    test_xml_filename = "test97.xml"
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<root>
    <data>
        <tag id="1">First item</tag>
        <tag id="2">Second item</tag>
        <tag id="admin">Admin item</tag>
    </data>
    <other>
        <tag id="100">Other item</tag>
    </other>
</root>"""
    with open(test_xml_filename, "w") as f:
        f.write(xml_content)

    # --- Test Cases ---
    test_cases = [
        ("1", "First item"),
        ("100", "Other item"),
        ("999", "Not found"),
        ("' or '1'='1", "Not found"),  # Malicious input for injection test
        ("admin", "Admin item")
    ]
    
    print("Running Python Test Cases...")
    for i, (id_val, expected) in enumerate(test_cases):
        result = perform_xpath_query(id_val, test_xml_filename)
        status = "PASSED" if result == expected else "FAILED"
        print(f"Test {i + 1}: id='{id_val}'\n  - Expected: {expected}\n  - Got: {result}\n  - Status: {status}\n")

    # Cleanup the test file
    os.remove(test_xml_filename)

if __name__ == "__main__":
    main()