from database.database import get_connection
from auth.password import hash_password, verify_password
from auth.session import get_current_user
from auth.rbac import has_permission

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."

    if not any(char.isupper() for char in password):
        return False, "Password must contain an uppercase letter."

    if not any(char.islower() for char in password):
        return False, "Password must contain a lowercase letter."

    if not any(char.isdigit() for char in password):
        return False, "Password must contain a number."

    return True, "Password is valid."

def create_user(username, password, role):
    # Check whether someone is logged in
    user = get_current_user()

    if user is None:
        return False, "Please login first."

    # Check Admin permission
    if not has_permission("MANAGE_USERS"):
        return False, "Access denied. Admin permission required."

    # Only allow valid roles
    valid_roles = ["ADMIN", "OPERATOR", "INVESTIGATOR"]

    if role not in valid_roles:
        return False, "Invalid role."
    valid, message = validate_password(password)

    if not valid:
        return False, message

    password_hash = hash_password(password)

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO users
            (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, role)
        )

        connection.commit()

        return True, "User created successfully!"

    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            return False, "Username already exists."

        return False, "Error creating user."

    finally:
        connection.close()
def disable_user(username):
    # Check who is currently logged in
    user = get_current_user()

    if user is None:
        return False, "Please login first."

    # Only Admin can disable users
    if not has_permission("MANAGE_USERS"):
        return False, "Access denied. Admin permission required."

    connection = get_connection()

    # Check the target user
    cursor = connection.execute(
        """
        SELECT id, role, is_active
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    target = cursor.fetchone()

    if target is None:
        connection.close()
        return False, "User not found."

    target_id, target_role, is_active = target

    # Prevent disabling the last active Admin
    if target_role == "ADMIN" and is_active == 1:

        cursor = connection.execute(
            """
            SELECT COUNT(*)
            FROM users
            WHERE role = 'ADMIN'
            AND is_active = 1
            """
        )

        admin_count = cursor.fetchone()[0]

        if admin_count <= 1:
            connection.close()
            return False, "Cannot disable the last active Admin."

    # Disable user
    connection.execute(
        """
        UPDATE users
        SET is_active = 0
        WHERE id = ?
        """,
        (target_id,)
    )

    connection.commit()
    connection.close()

    return True, "User disabled successfully."
def change_role(username, new_role):
    # Check who is logged in
    user = get_current_user()

    if user is None:
        return False, "Please login first."

    # Only Admin can change roles
    if not has_permission("MANAGE_USERS"):
        return False, "Access denied. Admin permission required."

    # Check valid roles
    valid_roles = ["ADMIN", "OPERATOR", "INVESTIGATOR"]

    if new_role not in valid_roles:
        return False, "Invalid role."

    connection = get_connection()

    cursor = connection.execute(
        """
        UPDATE users
        SET role = ?
        WHERE username = ?
        """,
        (new_role, username)
    )

    connection.commit()
    connection.close()

    if cursor.rowcount == 0:
        return False, "User not found."

    return True, "Role changed successfully."
def get_all_users():
    # Only Admin can view users
    if not has_permission("MANAGE_USERS"):
        return []

    connection = get_connection()

    cursor = connection.execute(
        """
        SELECT id, username, role, is_active, created_at
        FROM users
        ORDER BY id
        """
    )

    users = cursor.fetchall()

    connection.close()

    return users
def enable_user(username):
    # Check who is currently logged in
    user = get_current_user()

    if user is None:
        return False, "Please login first."

    # Only Admin can enable users
    if not has_permission("MANAGE_USERS"):
        return False, "Access denied. Admin permission required."

    connection = get_connection()

    cursor = connection.execute(
        """
        UPDATE users
        SET is_active = 1
        WHERE username = ?
        """,
        (username,)
    )

    connection.commit()
    connection.close()

    if cursor.rowcount == 0:
        return False, "User not found."

    return True, "User enabled successfully."
def change_password(old_password, new_password):
    # Check whether someone is logged in
    user = get_current_user()

    if user is None:
        return False, "Please login first."

    connection = get_connection()

    # Get current password hash
    cursor = connection.execute(
        """
        SELECT password_hash
        FROM users
        WHERE id = ?
        """,
        (user["id"],)
    )

    result = cursor.fetchone()

    if result is None:
        connection.close()
        return False, "User not found."

    current_password_hash = result[0]

    # Check old password
    if not verify_password(old_password, current_password_hash):
        connection.close()
        return False, "Current password is incorrect."
    valid, message = validate_password(new_password)

    if not valid:
        return False, message
    # Hash new password
    new_password_hash = hash_password(new_password)

    # Save new password
    connection.execute(
        """
        UPDATE users
        SET password_hash = ?,
            failed_attempts = 0,
            locked_until = NULL
        WHERE id = ?
        """,
        (new_password_hash, user["id"])
    )

    connection.commit()
    connection.close()

    return True, "Password changed successfully."