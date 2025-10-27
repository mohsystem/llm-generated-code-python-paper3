
from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import cgi
from urllib.parse import parse_qs

UPLOAD_DIR = "uploads"
PORT = 8000

class Lse71(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """\n            <html>\n            <body>\n                <h2>File Upload Application</h2>\n                <form action='/upload' method='post' enctype='multipart/form-data'>\n                    <input type='file' name='file' required><br><br>\n                    <input type='submit' value='Upload File'>\n                </form>\n            </body>\n            </html>\n            """
            self.wfile.write(html.encode())
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == '/upload':
            content_type = self.headers['Content-Type']
            if 'multipart/form-data' in content_type:
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={
                        'REQUEST_METHOD': 'POST',
                        'CONTENT_TYPE': content_type
                    }
                )
                
                if 'file' in form:
                    fileitem = form['file']
                    if fileitem.filename:
                        filename = os.path.basename(fileitem.filename)
                        filepath = os.path.join(UPLOAD_DIR, filename)
                        
                        with open(filepath, 'wb') as f:
                            f.write(fileitem.file.read())
                        
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        response = f"""\n                        <html>\n                        <body>\n                            <h2>File uploaded successfully!</h2>\n                            <p>Filename: {filename}</p>\n                            <a href='/'>Upload another file</a>\n                        </body>\n                        </html>\n                        """
                        self.wfile.write(response.encode())
                        return
            
            self.send_error(400, "Bad Request")

def run_server():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    server = HTTPServer(('localhost', PORT), Lse71)
    print(f"Server started on port {PORT}")
    print(f"Open http://localhost:{PORT} in your browser")
    server.serve_forever()

if __name__ == '__main__':
    run_server()
