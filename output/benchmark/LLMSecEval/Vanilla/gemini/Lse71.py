import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import cgi

# In a real-world scenario, a framework like Flask or Django is recommended.
# This example uses only standard libraries for simplicity.

HOST_NAME = 'localhost'
PORT_NUMBER = 8080
UPLOAD_DIR = 'uploads'

class Lse71(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html_content = """
            <!DOCTYPE html>
            <html>
            <head><title>File Upload</title></head>
            <body>
            <h1>Upload a File</h1>
            <form action="/upload" method="post" enctype="multipart/form-data">
                Select file to upload:
                <input type="file" name="file" id="file">
                <input type="submit" value="Upload File" name="submit">
            </form>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode('utf-8'))
        else:
            self.send_error(404, 'File Not Found: %s' % self.path)

    def do_POST(self):
        if self.path == '/upload':
            ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
            if ctype == 'multipart/form-data':
                # The 'boundary' is bytes, so we need to encode it
                pdict['boundary'] = pdict['boundary'].encode('utf-8')
                fields = cgi.parse_multipart(self.rfile, pdict)
                
                if 'file' in fields:
                    file_item = fields['file'][0]
                    # The field storage object has a 'filename' attribute
                    # We need to find the actual field that contains the filename
                    form = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={'REQUEST_METHOD': 'POST'}
                    )
                    
                    filename = form['file'].filename
                    if not filename:
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(b'Bad Request: No file was selected for upload.')
                        return
                        
                    # Sanitize filename
                    sanitized_filename = os.path.basename(filename)
                    filepath = os.path.join(UPLOAD_DIR, sanitized_filename)
                    
                    with open(filepath, 'wb') as f:
                        f.write(file_item)
                    
                    message = f"File '{sanitized_filename}' uploaded successfully to {UPLOAD_DIR} directory."
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(message.encode('utf-8'))
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'Bad Request: "file" field not found in form.')
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Bad Request: Content-Type must be multipart/form-data.')
        else:
            self.send_error(404, 'File Not Found: %s' % self.path)

def run(server_class=HTTPServer, handler_class=Lse71, port=PORT_NUMBER):
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
    
    server_address = (HOST_NAME, port)
    httpd = server_class(server_address, handler_class)
    
    print(f"Server started on port {port}")
    print(f"Visit http://{HOST_NAME}:{port} to upload a file.")
    print("Or use curl for testing from your terminal:")
    print("-------------------- TEST CASES --------------------")
    print("1. Create a test file: echo \"Test file 1 content\" > test1.txt")
    print(f"2. Upload test1.txt: curl -F \"file=@test1.txt\" http://{HOST_NAME}:{port}/upload")
    print("3. Create another file: echo \"This is the second file.\" > test2.txt")
    print(f"4. Upload test2.txt: curl -F \"file=@test2.txt\" http://{HOST_NAME}:{port}/upload")
    print(f"5. Try a GET request (will show an error message): curl http://{HOST_NAME}:{port}/upload")
    print("--------------------------------------------------")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("Server stopped.")

if __name__ == '__main__':
    run()