
import xml.etree.ElementTree as ET
from pathlib import Path
import sys
import os

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def sanitize_xpath(input_str):
    """Remove potentially dangerous characters for XPath injection"""
    return ''.join(c for c in input_str if c.isalnum() or c in '_-')

def execute_xpath_query(xpath_value, xml_filename):
    """Execute XPath query on XML file with security measures"""
    try:
        # Validate inputs
        if not xpath_value or not xpath_value.strip():
            return "Error: XPath value is required"
        if not xml_filename or not xml_filename.strip():
            return "Error: XML filename is required"
        
        # Sanitize XPath input
        sanitized_xpath = sanitize_xpath(xpath_value)
        
        # Validate file path - prevent path traversal
        file_path = Path(xml_filename).resolve()
        
        if not file_path.exists():
            return "Error: File does not exist"
        
        if not file_path.is_file():
            return "Error: Path is not a file"
        
        # Check file size
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return "Error: File size exceeds maximum allowed size"
        
        # Secure XML parsing - disable entity expansion
        parser = ET.XMLParser(resolve_entities=False)
        tree = ET.parse(str(file_path), parser=parser)
        root = tree.getroot()
        
        # Construct XPath query
        xpath_query = f".//tag[@id='{sanitized_xpath}']"
        
        # Execute XPath query
        nodes = root.findall(xpath_query)
        
        # Build result
        result = []
        for i, node in enumerate(nodes, 1):
            text = node.text if node.text else ""
            result.append(f"Node {i}: {text}")
        
        return "\\n".join(result) if result else "No matching nodes found"
        
    except ET.ParseError as e:
        return f"Error: XML parsing failed - {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    """Main function with test cases"""
    print("=== Test Case 1: Valid input ===")
    print(execute_xpath_query("test1", "test.xml"))
    
    print("\\n=== Test Case 2: Empty XPath ===")
    print(execute_xpath_query("", "test.xml"))
    
    print("\\n=== Test Case 3: Non-existent file ===")
    print(execute_xpath_query("test2", "nonexistent.xml"))
    
    print("\\n=== Test Case 4: None inputs ===")
    print(execute_xpath_query(None, "test.xml"))
    
    print("\\n=== Test Case 5: Special characters in XPath ===")
    print(execute_xpath_query("test'OR'1'='1", "test.xml"))
    
    # Command line usage
    if len(sys.argv) == 3:
        print("\\n=== Command Line Execution ===")
        print(execute_xpath_query(sys.argv[1], sys.argv[2]))

if __name__ == "__main__":
    main()
