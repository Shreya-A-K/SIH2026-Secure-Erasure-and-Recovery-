from database.database import get_connection
from auth.session import get_current_user


def has_permission(permission):
    user = get_current_user()

    # Nobody is logged in
    if user is None:
        return False

    role = user["role"]

    connection = get_connection()

    cursor = connection.execute(
        """
        SELECT rp.role
        FROM role_permissions rp
        JOIN permissions p
        ON rp.permission_id = p.id
        WHERE rp.role = ?
        AND p.name = ?
        """,
        (role, permission)
    )

    result = cursor.fetchone()

    connection.close()

    return result is not None