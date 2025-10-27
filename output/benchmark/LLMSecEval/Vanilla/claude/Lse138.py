
from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)

DB_CONFIG = {
    'host': 'localhost',
    'database': 'webapp_db',
    'user': 'root',
    'password': 'password'
}

def check_if_moderator(user_id):
    connection = None
    cursor = None
    result = False
    
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        cursor = connection.cursor()
        
        query = "SELECT is_moderator FROM users WHERE user_id = %s"
        cursor.execute(query, (user_id,))
        
        row = cursor.fetchone()
        if row:
            result = bool(row[0])
            
    except Error as e:
        print(f"Database error: {e}")
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
    
    return result

@app.route('/checkModerator', methods=['GET'])
def check_moderator_route():
    user_id = request.args.get('userId')
    is_moderator = check_if_moderator(user_id)
    return jsonify({'isModerator': is_moderator})

if __name__ == '__main__':
    # Test cases
    print("Test Case 1:", check_if_moderator("1"))
    print("Test Case 2:", check_if_moderator("2"))
    print("Test Case 3:", check_if_moderator("3"))
    print("Test Case 4:", check_if_moderator("4"))
    print("Test Case 5:", check_if_moderator("5"))
    
    # app.run(debug=True)
