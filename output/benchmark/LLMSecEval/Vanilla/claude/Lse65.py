from http.server import HTTPServer, BaseHTTPRequestHandler
import cgi
import os
from io import BytesIO

class Lse65:
    @staticmethod
    def handle_file_upload(file_content, filename):
        # Create uploads directory if it doesn't exist
        if not os.path.exists('uploads'):
            os.makedirs('uploads')

        # Save the file
        filepath = os.path.join('uploads', filename)
        with open(filepath, 'wb') as f:
            f.write(file_content)

        return filepath


class FileUploadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            html = '''
            <html>
            <body>
                <form action="/upload" method="post" enctype="multipart/form-data">
                    <input type="file" name="pdfFile" accept=".pdf">
                    <input type="submit" value="Upload PDF">
                </form>
            </body>
            </html>
            '''
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())

    def do_POST(self):
        if self.path == '/upload':
            content_type = self.headers['Content-Type']

            if 'multipart/form-data' in content_type:
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={
                        'REQUEST_METHOD': 'POST',
                        'CONTENT_TYPE': content_type,
                    }
                )

                if 'pdfFile' in form:
                    fileitem = form['pdfFile']
                    if fileitem.filename:
                        filename = os.path.basename(fileitem.filename)
                        file_content = fileitem.file.read()

                        Lse65.handle_file_upload(file_content, filename)

                        response = b'File uploaded successfully!'
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(response)
                        return

            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Bad Request')


def main():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, FileUploadHandler)
    print('Server started on port 8000')
    print('Open http://localhost:8000 in your browser')
    httpd.serve_forever()


if __name__ == '__main__':
    main()
