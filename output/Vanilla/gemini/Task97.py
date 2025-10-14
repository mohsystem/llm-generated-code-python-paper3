import os
# The 'lxml' library is a third-party library and needs to be installed.
# You can install it using pip: pip install lxml
try:
    from lxml import etree
except ImportError:
    print("Python code requires 'lxml' library. Please install it using 'pip install lxml'")
    etree = None

def evaluate_xpath(xml_file_name, xpath_expression):
    """
    Executes an XPath query on a given XML file using the lxml library.
    
    :param xml_file_name: The path to the XML file.
    :param xpath_expression: The XPath expression to evaluate.
    :return: A string representation of the result, or an error message.
    """
    if not etree:
        return "Error: lxml library not found."
    try:
        tree = etree.parse(xml_file_name)
        result = tree.xpath(xpath_expression)

        if isinstance(result, list):
            # Convert all items in the list to their string representation
            str_results = [str(item).strip() for item in result]
            return ", ".join(str_results)
        elif isinstance(result, float):
            # Format numbers to be consistent (e.g., 4.0 -> "4")
            return str(int(result)) if result.is_integer() else str(result)
        else:
            # Handle other single-value types like strings
            return str(result)

    except Exception as e:
        return f"Error: {e}"

def main():
    """Main function to run test cases."""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
    <book id="1">
        <title>The Lord of the Rings</title>
        <author>J.R.R. Tolkien</author>
        <year>1954</year>
    </book>
    <book id="2">
        <title>Pride and Prejudice</title>
        <author>Jane Austen</author>
        <year>1813</year>
    </book>
    <section name="fantasy">
         <book id="3">
            <title>A Game of Thrones</title>
            <author>George R. R. Martin</author>
            <year>1996</year>
        </book>
    </section>
    <book id="4">
        <title>The Hobbit</title>
        <author>J.R.R. Tolkien</author>
        <year>1937</year>
    </book>
</bookstore>"""
    file_name = "test.xml"
    
    try:
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(xml_content)
    except IOError as e:
        print(f"Failed to create test file: {e}")
        return

    test_cases = [
        ("/bookstore/book[@id='1']/title/text()", "The Lord of the Rings"),
        ("//book[@id='3']/author/text()", "George R. R. Martin"),
        ("/bookstore/book[author='J.R.R. Tolkien']/title/text()", "The Lord of the Rings, The Hobbit"),
        ("count(//book)", "4"),
        ("//section/@name", "fantasy")
    ]

    print("--- Python Test Cases ---")
    for xpath, expected in test_cases:
        result = evaluate_xpath(file_name, xpath)
        print(f"XPath: {xpath}")
        print(f"Result: {result}")
        print(f"Expected: {expected}")
        print(f"Status: {'Passed' if result == expected else 'Failed'}")
        print()
    
    try:
        os.remove(file_name)
    except OSError as e:
        print(f"Failed to delete test file: {e}")

if __name__ == "__main__":
    main()