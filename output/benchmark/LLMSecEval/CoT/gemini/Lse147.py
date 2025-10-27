import sqlite3
from sqlite3 import Error

def create_connection(db_file=":memory:"):
    """ Create a database connection to a SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return conn

def create_table(conn):
    """ Create the orders table """
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY,
        stock_name TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        order_date DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
        print("Table 'orders' is ready.")
    except Error as e:
        print(e)

def buy_order(conn, stock_name, quantity):
    """
    In a real web application (e.g., using Flask or Django), this function
    would be the logic for the /buy_order route. It would receive stock_name
    and quantity from the request form, insert into the DB, and then
    return a redirect to the /stock_view page.

    This simulation focuses on the secure database insertion logic.
    
    :param conn: Connection object
    :param stock_name: The name of the stock
    :param quantity: The quantity of the stock
    :return: True on success, False on failure
    """
    # Using a parameterized query (with '?') prevents SQL injection.
    # The database driver safely handles the values.
    sql = ''' INSERT INTO orders(stock_name, quantity)
              VALUES(?,?) '''
    try:
        cur = conn.cursor()
        cur.execute(sql, (stock_name, quantity))
        conn.commit()
        print(f"Successfully inserted order for {quantity} of {stock_name}")
        # In Flask, you would do: return redirect(url_for('stock_view'))
        return True
    except Error as e:
        print(f"Error inserting order: {e}")
        return False

def view_orders(conn):
    """
    Query all rows in the orders table
    :param conn: the Connection object
    """
    print("\n--- Current Orders in Database ---")
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, stock_name, quantity, order_date FROM orders")
        rows = cur.fetchall()
        for row in rows:
            print(f"ID: {row[0]}, Stock: {row[1]}, Quantity: {row[2]}, Date: {row[3]}")
    except Error as e:
        print(f"Error viewing orders: {e}")
    print("--------------------------------\n")


if __name__ == '__main__':
    # Using an in-memory database for this example
    conn = create_connection()

    if conn is not None:
        create_table(conn)
        
        # --- 5 Test Cases ---
        print("\n--- Running 5 Test Cases ---")
        buy_order(conn, "AAPL", 10)
        buy_order(conn, "GOOGL", 5)
        buy_order(conn, "MSFT", 15)
        buy_order(conn, "AMZN", 2)
        # Test case with a potentially malicious name to show safety
        buy_order(conn, "TSLA'); DROP TABLE orders; --", 1)
        print("--- Test Cases Finished ---\n")
        
        # View all orders to verify insertions
        view_orders(conn)
        
        conn.close()
        print("Database connection closed.")
    else:
        print("Error! cannot create the database connection.")