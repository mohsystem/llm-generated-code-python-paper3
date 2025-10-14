
import xml.etree.ElementTree as ET
from typing import List, Any, Dict, Optional
import hashlib
import secrets
import base64

MAX_REQUEST_SIZE = 1048576  # 1MB


def escape_xml(text: str) -> str:
    """Escape XML special characters."""
    if text is None:
        return ""
    return (text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;"))


def create_xml_rpc_request(method_name: str, params: List[Any]) -> str:
    """Create an XML-RPC request string."""
    xml_parts = ['<?xml version="1.0"?>', '<methodCall>']
    xml_parts.append(f'<methodName>{escape_xml(method_name)}</methodName>')
    xml_parts.append('<params>')
    
    for param in params:
        xml_parts.append('<param><value>')
        if isinstance(param, int):
            xml_parts.append(f'<int>{param}</int>')
        elif isinstance(param, str):
            xml_parts.append(f'<string>{escape_xml(param)}</string>')
        xml_parts.append('</value></param>')
    
    xml_parts.append('</params>')
    xml_parts.append('</methodCall>')
    return ''.join(xml_parts)


def create_success_response(value: Any) -> str:
    """Create a successful XML-RPC response."""
    xml_parts = ['<?xml version="1.0"?>', '<methodResponse>']
    xml_parts.append('<params><param><value>')
    
    if isinstance(value, int):
        xml_parts.append(f'<int>{value}</int>')
    elif isinstance(value, str):
        xml_parts.append(f'<string>{escape_xml(value)}</string>')
    
    xml_parts.append('</value></param></params>')
    xml_parts.append('</methodResponse>')
    return ''.join(xml_parts)


def create_fault_response(code: int, message: str) -> str:
    """Create a fault XML-RPC response."""
    xml_parts = ['<?xml version="1.0"?>', '<methodResponse>']
    xml_parts.append('<fault><value><struct>')
    xml_parts.append(f'<member><name>faultCode</name><value><int>{code}</int></value></member>')
    xml_parts.append(f'<member><name>faultString</name><value><string>{escape_xml(message)}</string></value></member>')
    xml_parts.append('</struct></value></fault>')
    xml_parts.append('</methodResponse>')
    return ''.join(xml_parts)


def hash_with_salt(input_str: str) -> str:
    """Hash a string with a random salt using SHA-256."""
    salt = secrets.token_bytes(16)
    hash_obj = hashlib.sha256()
    hash_obj.update(salt)
    hash_obj.update(input_str.encode('utf-8'))
    hash_bytes = hash_obj.digest()
    
    salt_b64 = base64.b64encode(salt).decode('ascii')
    hash_b64 = base64.b64encode(hash_bytes).decode('ascii')
    return f"{salt_b64}:{hash_b64}"


def execute_method(method_name: str, params: List[Any]) -> str:
    """Execute the requested method with parameters."""
    try:
        if method_name == "add":
            if len(params) != 2 or not all(isinstance(p, int) for p in params):
                return create_fault_response(-32602, "Invalid params: add requires two integers")
            result = params[0] + params[1]
            return create_success_response(result)
        
        elif method_name == "multiply":
            if len(params) != 2 or not all(isinstance(p, int) for p in params):
                return create_fault_response(-32602, "Invalid params: multiply requires two integers")
            result = params[0] * params[1]
            return create_success_response(result)
        
        elif method_name == "echo":
            if len(params) != 1 or not isinstance(params[0], str):
                return create_fault_response(-32602, "Invalid params: echo requires one string")
            return create_success_response(params[0])
        
        elif method_name == "hashString":
            if len(params) != 1 or not isinstance(params[0], str):
                return create_fault_response(-32602, "Invalid params: hashString requires one string")
            hashed = hash_with_salt(params[0])
            return create_success_response(hashed)
        
        else:
            return create_fault_response(-32601, f"Method not found: {method_name}")
    
    except Exception:
        return create_fault_response(-32603, "Internal error")


def handle_request(xml_request: str) -> str:
    """Handle an XML-RPC request and return a response."""
    if not xml_request:
        return create_fault_response(-32700, "Parse error: Empty request")
    
    if len(xml_request) > MAX_REQUEST_SIZE:
        return create_fault_response(-32700, "Parse error: Request too large")
    
    try:
        # Parse XML with security measures
        parser = ET.XMLParser()
        parser.entity = {}  # Disable entity processing
        
        root = ET.fromstring(xml_request, parser=parser)
        
        # Extract method name
        method_name_elem = root.find('methodName')
        if method_name_elem is None or not method_name_elem.text:
            return create_fault_response(-32600, "Invalid Request: No method name")
        
        method_name = method_name_elem.text.strip()
        
        # Extract parameters
        params = []
        params_elem = root.find('params')
        if params_elem is not None:
            for param_elem in params_elem.findall('param'):
                value_elem = param_elem.find('value')
                if value_elem is not None:
                    int_elem = value_elem.find('int')
                    string_elem = value_elem.find('string')
                    
                    if int_elem is not None:
                        try:
                            params.append(int(int_elem.text))
                        except (ValueError, TypeError):
                            return create_fault_response(-32602, "Invalid params: Invalid integer value")
                    elif string_elem is not None:
                        params.append(string_elem.text if string_elem.text else "")
        
        return execute_method(method_name, params)
    
    except ET.ParseError:
        return create_fault_response(-32700, "Parse error: Invalid XML")
    except Exception:
        return create_fault_response(-32700, "Parse error: Invalid XML")


def main() -> None:
    """Main function with test cases."""
    print("=== XML-RPC Server Test Cases ===\\n")
    
    # Test Case 1: Add two numbers
    request1 = create_xml_rpc_request("add", [5, 3])
    response1 = handle_request(request1)
    print("Test 1 - Add(5, 3):")
    print(f"Response: {response1}\\n")
    
    # Test Case 2: Multiply two numbers
    request2 = create_xml_rpc_request("multiply", [4, 7])
    response2 = handle_request(request2)
    print("Test 2 - Multiply(4, 7):")
    print(f"Response: {response2}\\n")
    
    # Test Case 3: Echo string
    request3 = create_xml_rpc_request("echo", ["Hello World"])
    response3 = handle_request(request3)
    print("Test 3 - Echo('Hello World'):")
    print(f"Response: {response3}\\n")
    
    # Test Case 4: Invalid method
    request4 = create_xml_rpc_request("invalidMethod", [1])
    response4 = handle_request(request4)
    print("Test 4 - Invalid Method:")
    print(f"Response: {response4}\\n")
    
    # Test Case 5: Hash string
    request5 = create_xml_rpc_request("hashString", ["testdata"])
    response5 = handle_request(request5)
    print("Test 5 - HashString('testdata'):")
    print(f"Response: {response5}\\n")


if __name__ == "__main__":
    main()
