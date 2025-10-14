
import xml.etree.ElementTree as ET
import os
import re

def execute_xpath_query(xpath_value, xml_file_name):
    try:
        # Validate inputs
        if not xpath_value or not xpath_value.strip():
            return "Error: XPath value cannot be empty"
        if not xml_file_name or not xml_file_name.strip():
            return "Error: XML file name cannot be empty"
        
        # Sanitize xpath value to prevent injection
        sanitized_xpath = re.sub(r'[^a-zA-Z0-9_-]', '', xpath_value)
        
        # Check if file exists
        if not os.path.isfile(xml_file_name):
            return "Error: XML file not found or invalid"
        
        # Parse XML file with security considerations
        parser = ET.XMLParser()
        parser.entity = {}  # Disable entity expansion
        tree = ET.parse(xml_file_name, parser=parser)
        root = tree.getroot()
        
        # Execute XPath query
        xpath_expression = f".//*[@id='{sanitized_xpath}']"
        elements = root.findall(xpath_expression)
        
        result = []
        for element in elements:
            text = element.text if element.text else ""
            result.append(f"{element.tag}: {text}")
        
        return "\\n".join(result) if result else "No results found"
        
    except ET.ParseError as e:
        return f"Error parsing XML: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    # Test cases
    print("Test Case 1:")
    print(execute_xpath_query("test1", "test.xml"))
    print()
    
    print("Test Case 2:")
    print(execute_xpath_query("test2", "test.xml"))
    print()
    
    print("Test Case 3:")
    print(execute_xpath_query("", "test.xml"))
    print()
    
    print("Test Case 4:")
    print(execute_xpath_query("test1", "nonexistent.xml"))
    print()
    
    print("Test Case 5:")
    print(execute_xpath_query("invalid-id", "test.xml"))

if __name__ == "__main__":
    main()
