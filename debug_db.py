try:
    import mysql.connector
    print("mysql.connector imported successfully")
except ImportError as e:
    print(f"Failed to import mysql.connector: {e}")

from config import Config

try:
    conn = mysql.connector.connect(
        host=Config.MYSQL_HOST,
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB
    )
    print("Database connection successful")
    cursor = conn.cursor()
    cursor.execute("SELECT 1")
    print("Query executed successfully")
    conn.close()
except Exception as e:
    print(f"Database connection failed: {e}")
