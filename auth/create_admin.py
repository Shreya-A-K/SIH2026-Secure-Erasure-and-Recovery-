from getpass import getpass

from database.database import get_connection
from auth.password import hash_password
from auth.user_manager import validate_password


def create_admin():
    connection = get_connection()

    # Check whether an Admin already exists
    cursor = connection.execute(
        """
        SELECT COUNT(*)
        FROM users
        WHERE role = 'ADMIN'
        """
    )

    admin_count = cursor.fetchone()[0]

    if admin_count > 0:
        connection.close()
        print("Admin account already exists.")
        return

    connection.close()

    print("Create the initial Admin account.")

    username = input("Enter Admin username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    password = getpass("Enter Admin password: ")
    confirm_password = getpass("Confirm Admin password: ")

    if password != confirm_password:
        print("Passwords do not match.")
        return

    valid, message = validate_password(password)

    if not valid:
        print(message)
        return

    password_hash = hash_password(password)

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO users
            (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, "ADMIN")
        )

        connection.commit()

        print("Initial Admin account created successfully!")

    except Exception as e:
        print("Error creating Admin account.")
        print(e)

    finally:
        connection.close()


if __name__ == "__main__":
    create_admin()
