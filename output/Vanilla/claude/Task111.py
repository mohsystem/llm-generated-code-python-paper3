
import socket
import re
from typing import Any, List, Callable, Dict

class Task111:
    def __init__(self, port: int = 8080):
        self.port = port
        self.methods: Dict[str, Callable] = {
            'add': lambda params: params[0] + params[1],
            'subtract': lambda params: params[0] - params[1],
            'multiply': lambda params: params[0] * params[1],
            'greet': lambda params: f"Hello, {params[0]}!",
            'concat': lambda params: params[0] + params[1]
        }
    
    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', self.port))
        server_socket.listen(5)
        print(f"XML-RPC Server started on port {self.port}")
        
        try:
            while True:
                client_socket, address = server_socket.accept()
                self.handle_client(client_socket)
        except KeyboardInterrupt:
            print("\\nServer shutting down...")
        finally:
            server_socket.close()
    
    def handle_client(self, client_socket: socket.socket):
        try:
            request = client_socket.recv(4096).decode('utf-8')
            
            lines = request.split('\\r\\n')
            content_length = 0
            body_start = 0
            
            for i, line in enumerate(lines):
                if line.startswith('Content-Length:'):
                    content_length = int(line.split(':')[1].strip())
                if line == '':
                    body_start = i + 1
                    break
            
            body = '\\r\\n'.join(lines[body_start:])
            
            response = self.process_xmlrpc(body)
            
            http_response = (
                "HTTP/1.1 200 OK\\r\\n"
                "Content-Type: text/xml\\r\\n"
                f"Content-Length: {len(response)}\\r\\n"
                "\\r\\n"
                f"{response}"
            )
            
            client_socket.sendall(http_response.encode('utf-8'))
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()
    
    def process_xmlrpc(self, xml_request: str) -> str:
        try:
            method_name = self.extract_method_name(xml_request)
            params = self.extract_params(xml_request)
            
            if method_name in self.methods:
                result = self.methods[method_name](params)
                return self.build_success_response(result)
            else:
                return self.build_fault_response(-1, f"Method not found: {method_name}")
        except Exception as e:
            return self.build_fault_response(-2, f"Error processing request: {str(e)}")
    
    def extract_method_name(self, xml: str) -> str:
        match = re.search(r'<methodName>(.*?)</methodName>', xml)
        if match:
            return match.group(1)
        return ""
    
    def extract_params(self, xml: str) -> List[Any]:
        params = []
        param_matches = re.finditer(r'<param>.*?<value>(.*?)</value>.*?</param>', xml, re.DOTALL)
        
        for match in param_matches:
            value_content = match.group(1)
            
            int_match = re.search(r'<(?:int|i4)>(.*?)</(?:int|i4)>', value_content)
            if int_match:
                params.append(int(int_match.group(1)))
                continue
            
            string_match = re.search(r'<string>(.*?)</string>', value_content)
            if string_match:
                params.append(string_match.group(1))
                continue
            
            params.append(value_content.strip())
        
        return params
    
    def build_success_response(self, result: Any) -> str:
        value_tag = ""
        if isinstance(result, int):
            value_tag = f"<int>{result}</int>"
        elif isinstance(result, str):
            value_tag = f"<string>{result}</string>"
        else:
            value_tag = str(result)
        
        return (
            '<?xml version="1.0"?>\\n'
            '<methodResponse>\\n'
            '  <params>\\n'
            '    <param>\\n'
            f'      <value>{value_tag}</value>\\n'
            '    </param>\\n'
            '  </params>\\n'
            '</methodResponse>'
        )
    
    def build_fault_response(self, fault_code: int, fault_string: str) -> str:
        return (
            '<?xml version="1.0"?>\\n'
            '<methodResponse>\\n'
            '  <fault>\\n'
            '    <value>\\n'
            '      <struct>\\n'
            '        <member>\\n'
            '          <name>faultCode</name>\\n'
            f'          <value><int>{fault_code}</int></value>\\n'
            '        </member>\\n'
            '        <member>\\n'
            '          <name>faultString</name>\\n'
            f'          <value><string>{fault_string}</string></value>\\n'
            '        </member>\\n'
            '      </struct>\\n'
            '    </value>\\n'
            '  </fault>\\n'
            '</methodResponse>'
        )


if __name__ == "__main__":
    server = Task111()
    
    print("Test Case 1: Process add request")
    request1 = '<?xml version="1.0"?><methodCall><methodName>add</methodName><params><param><value><int>5</int></value></param><param><value><int>3</int></value></param></params></methodCall>'
    print(server.process_xmlrpc(request1))
    
    print("\\nTest Case 2: Process subtract request")
    request2 = '<?xml version="1.0"?><methodCall><methodName>subtract</methodName><params><param><value><int>10</int></value></param><param><value><int>4</int></value></param></params></methodCall>'
    print(server.process_xmlrpc(request2))
    
    print("\\nTest Case 3: Process multiply request")
    request3 = '<?xml version="1.0"?><methodCall><methodName>multiply</methodName><params><param><value><int>6</int></value></param><param><value><int>7</int></value></param></params></methodCall>'
    print(server.process_xmlrpc(request3))
    
    print("\\nTest Case 4: Process greet request")
    request4 = '<?xml version="1.0"?><methodCall><methodName>greet</methodName><params><param><value><string>Alice</string></value></param></params></methodCall>'
    print(server.process_xmlrpc(request4))
    
    print("\\nTest Case 5: Process invalid method request")
    request5 = '<?xml version="1.0"?><methodCall><methodName>invalidMethod</methodName><params></params></methodCall>'
    print(server.process_xmlrpc(request5))
