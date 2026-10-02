from database import get_db_connection
from werkzeug.security import generate_password_hash

username = "test_user"
password = "test123"

connection = get_db_connection()
cursor = connection.cursor()

password_hash = generate_password_hash(password)

cursor.execute("""
    UPDATE users
    SET password_hash = %s,
        role = %s
    WHERE username = %s
""", (password_hash, "USER", username))

connection.commit()

print("test_user password and role updated successfully!")

cursor.close()
connection.close()