from database import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash


def create_user(username, password):
    connection = get_db_connection()
    cursor = connection.cursor()

    password_hash = generate_password_hash(password)

    cursor.execute(
        """
        INSERT INTO users (username, password_hash)
        VALUES (%s, %s)
        """,
        (username, password_hash)
    )

    connection.commit()

    cursor.close()
    connection.close()


def get_user(username):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT id, username, password_hash, role
        FROM users
        WHERE username = %s
        """,
        (username,)
    )

    user = cursor.fetchone()

    cursor.close()
    connection.close()

    return user


def verify_password(password, password_hash):
    return check_password_hash(
        password_hash,
        password
    )