import os

class SimpleUploadedFile:
    def __init__(self, data: bytes):
        self.data = data
    def save(self, path: str):
        with open(path, 'wb') as f:
            f.write(self.data)

def upload_file(p: SimpleUploadedFile, filename: str) -> str:
    os.makedirs('uploads', exist_ok=True)
    path = os.path.join('uploads', filename)
    p.save(path)
    return os.path.abspath(path)

if __name__ == '__main__':
    print(upload_file(SimpleUploadedFile(b'Hello from Python 1'), 'py_test1.txt'))
    print(upload_file(SimpleUploadedFile(b'Hello from Python 2'), 'py_test2.txt'))
    print(upload_file(SimpleUploadedFile(b'Hello from Python 3'), 'py_test3.txt'))
    print(upload_file(SimpleUploadedFile(b'Hello from Python 4'), 'py_test4.txt'))
    print(upload_file(SimpleUploadedFile(b'Hello from Python 5'), 'py_test5.txt'))