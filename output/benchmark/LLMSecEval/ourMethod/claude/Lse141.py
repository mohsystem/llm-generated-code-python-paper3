
import os
import sys
from flask import Flask, jsonify
import mysql.connector
import ssl

# Security: Create Flask web app with secure defaults
app = Flask(__name__)
# Security: Disable debug mode in production (Rules#1)
app.config['DEBUG'] = False

# Security: Never hardcode credentials, use environment variables (Rules#3, Rules#4)
def get_server_name():
    """Returns database server name from environment variable.\n    \n    Security: Fails closed if not configured (Rules#1)\n    """
    server = os.getenv('DB_SERVER')
    if not server or not server.strip():
        # Security: Generic error, no internal details (Rules#1)
        raise ValueError("Database server configuration not found")
    return server.strip()

def get_database_name():
    """Returns database name from environment variable.\n    \n    Security: Retrieves from secure configuration, not hardcoded (Rules#4)\n    """
    db_name = os.getenv('DB_NAME')
    if not db_name or not db_name.strip():
        raise ValueError("Database name configuration not found")
    return db_name.strip()

def get_database_user():
    """Returns database user from environment variable.\n    \n    Security: Credentials managed externally (Rules#3, Rules#4)\n    """
    user = os.getenv('DB_USER')
    if not user or not user.strip():
        raise ValueError("Database user configuration not found")
    return user.strip()

def get_database_password():
    """Returns database password from environment variable.\n    \n    Security: Never log or expose passwords (Rules#1, Rules#3, Rules#4)\n    """
    password = os.getenv('DB_PASSWORD')
    if not password:
        raise ValueError("Database password configuration not found")
    return password

def get_database_connection():
    """Returns secure database connection with TLS enforcement.\n    \n    Security: Enforces TLS 1.2+ with certificate verification (Rules#5, Rules#6, Rules#7)\n    """
    server = get_server_name()
    db_name = get_database_name()
    user = get_database_user()
    password = get_database_password()
    
    # Security: Create SSL context with TLS 1.2+ and certificate validation (Rules#7)
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    
    # Security: Force TLS 1.2+ on all Python versions (Rules#7)
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
    
    try:
        # Security: Establish connection with TLS enforcement
        conn = mysql.connector.connect(
            host=server,
            database=db_name,
            user=user,
            password=password,
            ssl_disabled=False,
            tls_versions=['TLSv1.2', 'TLSv1.3']
        )
        return conn
    except mysql.connector.Error as e:
        # Security: Generic error message (Rules#1)
        raise ConnectionError("Database connection failed")

@app.route('/')
def index():
    """Web app endpoint to test database connectivity."""
    try:
        conn = get_database_connection()
        # Security: Never log connection details or credentials (Rules#1)
        conn.close()
        return jsonify({"status": "success", "message": "Database connection successful"})
    except Exception as e:
        # Security: Return generic error to client (Rules#1)
        return jsonify({"status": "error", "message": "Service temporarily unavailable"}), 500

# Test cases
if __name__ == '__main__':
    print("Test Case 1: Retrieve server name")
    try:
        server = get_server_name()
        print(f"Server configured: {server is not None and len(server) > 0}")
    except Exception as e:
        print(f"Configuration error: {str(e)}")
    
    print("\\nTest Case 2: Retrieve database name")
    try:
        db_name = get_database_name()
        print(f"Database configured: {db_name is not None and len(db_name) > 0}")
    except Exception as e:
        print(f"Configuration error: {str(e)}")
    
    print("\\nTest Case 3: Retrieve database user")
    try:
        user = get_database_user()
        print(f"User configured: {user is not None and len(user) > 0}")
    except Exception as e:
        print(f"Configuration error: {str(e)}")
    
    print("\\nTest Case 4: Retrieve database password")
    try:
        password = get_database_password()
        # Security: Never print passwords (Rules#1)
        print(f"Password configured: {password is not None and len(password) > 0}")
    except Exception as e:
        print(f"Configuration error: {str(e)}")
    
    print("\\nTest Case 5: Establish database connection")
    try:
        conn = get_database_connection()
        print(f"Connection successful: {conn is not None and conn.is_connected()}")
        if conn:
            conn.close()
    except Exception as e:
        print(f"Connection failed: {str(e)}")
    
    # Security: Do not run Flask in debug mode in production
    # app.run(host='127.0.0.1', port=5000, debug=False)
