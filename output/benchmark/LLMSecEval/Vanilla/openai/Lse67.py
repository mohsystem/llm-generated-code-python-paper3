import os
import mysql.connector

def _is_valid_identifier(name: str) -> bool:
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9_]+", name))

def store_image(file_path: str, conn_params: dict, table: str, rec_id: int) -> bool:
    if not _is_valid_identifier(table):
        raise ValueError("Invalid table name")

    if not os.path.isfile(file_path):
        print(f"File not found: {file_path}")
        return False

    filename = os.path.basename(file_path)
    create_sql = f"""
    CREATE TABLE IF NOT EXISTS {table} (
        id INT PRIMARY KEY,
        filename VARCHAR(255),
        data LONGBLOB
    )"""

    insert_sql = f"""
    INSERT INTO {table} (id, filename, data)
    VALUES (%s, %s, %s)
    ON DUPLICATE KEY UPDATE filename=VALUES(filename), data=VALUES(data)
    """

    conn = None
    try:
        conn = mysql.connector.connect(**conn_params)
        conn.autocommit = False
        cur = conn.cursor()

        cur.execute(create_sql)

        with open(file_path, "rb") as f:
            blob = f.read()

        cur.execute(insert_sql, (rec_id, filename, blob))
        conn.commit()
        return True
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error storing image: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    params = {
        "host": "localhost",
        "user": "root",
        "password": "root",
        "database": "testdb",
        "port": 3306
    }
    table = "images"

    print("Test 1:", store_image("test1.jpg", params, table, 1))
    print("Test 2:", store_image("test2.png", params, table, 2))
    print("Test 3:", store_image("test3.gif", params, table, 3))
    print("Test 4:", store_image("test4.bmp", params, table, 4))
    print("Test 5:", store_image("test5.webp", params, table, 5))