import mysql.connector
from config import Config

def migrate_db():
    try:
        conn = mysql.connector.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB
        )
        cursor = conn.cursor()
        
        # Add security_question column if not exists
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN security_question VARCHAR(255) NOT NULL DEFAULT 'What is your pet name?'")
            print("Added security_question column.")
        except mysql.connector.Error as err:
            if err.errno == 1060: # Duplicate column name
                print("security_question column already exists.")
            else:
                print(f"Error adding security_question: {err}")

        # Add security_answer_hash column if not exists
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN security_answer_hash VARCHAR(255) NOT NULL DEFAULT 'placeholder_hash'")
            print("Added security_answer_hash column.")
        except mysql.connector.Error as err:
            if err.errno == 1060:
                print("security_answer_hash column already exists.")
            else:
                print(f"Error adding security_answer_hash: {err}")
        
        conn.commit()
        conn.close()
        print("Migration complete.")
    except Exception as e:
        print(f"Migration failed: {e}")

if __name__ == "__main__":
    migrate_db()
