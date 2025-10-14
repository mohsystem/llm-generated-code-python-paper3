
import sqlite3
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

class Task49:
    DB_NAME = 'users.db'
    
    @staticmethod
    def init_database():
        conn = sqlite3.connect(Task49.DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                name TEXT NOT NULL,\n                email TEXT NOT NULL,\n                age INTEGER\n            )\n        ''')
        conn.commit()
        conn.close()
    
    @staticmethod
    def add_user(name, email, age):
        try:
            conn = sqlite3.connect(Task49.DB_NAME)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (name, email, age) VALUES (?, ?, ?)',
                         (name, email, age))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return json.dumps({"status": "success", "id": user_id})
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})
    
    @staticmethod
    def get_users():
        try:
            conn = sqlite3.connect(Task49.DB_NAME)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users')
            rows = cursor.fetchall()
            conn.close()
            
            users = []
            for row in rows:
                users.append({
                    "id": row[0],
                    "name": row[1],
                    "email": row[2],
                    "age": row[3]
                })
            return json.dumps(users)
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/users':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                name = data['name']
                email = data['email']
                age = data['age']
                
                response = Task49.add_user(name, email, age)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(response.encode())
            except Exception as e:
                response = json.dumps({"status": "error", "message": str(e)})
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(response.encode())
    
    def do_GET(self):
        if self.path == '/api/users':
            response = Task49.get_users()
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(response.encode())

def start_server(port=8080):
    Task49.init_database()
    server = HTTPServer(('localhost', port), RequestHandler)
    print(f'Server started on port {port}')
    server.serve_forever()

if __name__ == '__main__':
    Task49.init_database()
    
    print("Test Case 1: Add user John")
    print(Task49.add_user("John Doe", "john@example.com", 30))
    
    print("\\nTest Case 2: Add user Jane")
    print(Task49.add_user("Jane Smith", "jane@example.com", 25))
    
    print("\\nTest Case 3: Add user Bob")
    print(Task49.add_user("Bob Johnson", "bob@example.com", 35))
    
    print("\\nTest Case 4: Add user Alice")
    print(Task49.add_user("Alice Brown", "alice@example.com", 28))
    
    print("\\nTest Case 5: Get all users")
    print(Task49.get_users())
    
    # Uncomment to start server
    # start_server(8080)
