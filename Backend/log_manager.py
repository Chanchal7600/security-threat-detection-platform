from database import get_db_connection


def add_security_log(timestamp, source_ip, event_type, username, status, details):
    connection = get_db_connection()
    cursor = connection.cursor()

    query = """
        INSERT INTO security_logs
        (timestamp, source_ip, event_type, username, status, details)
        VALUES (%s, %s, %s, %s, %s, %s)
    """

    values = (
        timestamp,
        source_ip,
        event_type,
        username,
        status,
        details
    )

    cursor.execute(query, values)
    connection.commit()

    cursor.close()
    connection.close()

    print("Security log added successfully!")