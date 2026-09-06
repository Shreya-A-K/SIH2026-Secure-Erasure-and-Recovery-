from datetime import datetime, timedelta, timezone

from database.database import get_connection
from auth.password import verify_password


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def authenticate(username, password):
    connection = get_connection()

    cursor = connection.execute(
        """
        SELECT id, username, password_hash, role,
               is_active, failed_attempts, locked_until
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()

    if user is None:
        connection.close()
        return None

    (
        user_id,
        db_username,
        password_hash,
        role,
        is_active,
        failed_attempts,
        locked_until
    ) = user

    # Check whether account is active
    if is_active != 1:
        connection.close()
        return None

    # Check temporary lock
    if locked_until is not None:

        lock_time = datetime.fromisoformat(locked_until)
        current_time = datetime.now(timezone.utc)

        if current_time < lock_time:
            connection.close()
            return None

        # Lock expired → reset lock information
        failed_attempts = 0

        connection.execute(
            """
            UPDATE users
            SET failed_attempts = 0,
                locked_until = NULL
            WHERE id = ?
            """,
            (user_id,)
        )

        connection.commit()

    # Check password
    if verify_password(password, password_hash):

        connection.execute(
            """
            UPDATE users
            SET failed_attempts = 0,
                locked_until = NULL
            WHERE id = ?
            """,
            (user_id,)
        )

        connection.commit()
        connection.close()

        return {
            "id": user_id,
            "username": db_username,
            "role": role
        }

    # Wrong password
    failed_attempts += 1

    if failed_attempts >= MAX_FAILED_ATTEMPTS:

        lock_time = datetime.now(timezone.utc) + timedelta(
            minutes=LOCKOUT_MINUTES
        )

        connection.execute(
            """
            UPDATE users
            SET failed_attempts = ?,
                locked_until = ?
            WHERE id = ?
            """,
            (
                failed_attempts,
                lock_time.isoformat(),
                user_id
            )
        )

    else:

        connection.execute(
            """
            UPDATE users
            SET failed_attempts = ?
            WHERE id = ?
            """,
            (failed_attempts, user_id)
        )

    connection.commit()
    connection.close()

    return None


def unlock_user(username):
    from auth.rbac import has_permission

    # Only logged-in Admin can unlock users
    if not has_permission("MANAGE_USERS"):
        return False

    connection = get_connection()

    cursor = connection.execute(
        """
        UPDATE users
        SET failed_attempts = 0,
            locked_until = NULL
        WHERE username = ?
        """,
        (username,)
    )

    connection.commit()
    connection.close()

    return cursor.rowcount > 0