
from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)

class Lse138:
    def __init__(self):
        self.db_config = {
            'host': 'localhost',
            'user': 'root',
            'password': 'password',
            'database': 'webapp'
        }
    
    def check_if_moderator(self, username):
        if not username:
            return False
        
        try:
            connection = mysql.connector.connect(**self.db_config)
            cursor = connection.cursor(dictionary=True)
            
            query = "SELECT is_moderator FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            
            cursor.close()
            connection.close()
            
            if result:
                return result['is_moderator']
            return False
            
        except Error as e:
            print(f"Database error: {e}")
            return False
    
    @staticmethod
    def create_app():
        lse = Lse138()
        
        @app.route('/checkModerator', methods=['GET'])
        def check_moderator_route():
            username = request.args.get('username', '')
            is_moderator = lse.check_if_moderator(username)
            return jsonify({'isModerator': is_moderator})
        
        return app

if __name__ == '__main__':
    # Test cases
    lse = Lse138()
    test_users = ['admin', 'moderator1', 'user1', 'testmod', 'normaluser']
    
    print("Test Cases:")
    for user in test_users:
        result = lse.check_if_moderator(user)
        print(f"User: {user} - Is Moderator: {result}")
    
    # Run the web app
    web_app = Lse138.create_app()
    web_app.run(debug=True, port=5000)
