from database.database import (
    create_users_table,
    add_login_security_columns,
    create_rbac_tables,
    create_permissions,
    create_role_permissions
)

from auth.password import hash_password
from database.database import get_connection


def seed_default_users():
    conn = get_connection()
    defaults = [
        ("admin", "Admin@123456", "ADMIN"),
        ("operator1", "Operator@123", "OPERATOR"),
        ("investigator1", "Investigator@123", "INVESTIGATOR"),
    ]
    for username, password, role in defaults:
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        if not cur.fetchone():
            pwd_hash = hash_password(password)
            conn.execute(
                "INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, 1)",
                (username, pwd_hash, role),
            )
    conn.commit()
    conn.close()


def init_database(seed_defaults: bool = True):
    create_users_table()
    add_login_security_columns()
    create_rbac_tables()
    create_permissions()
    create_role_permissions()
    if seed_defaults:
        seed_default_users()


def setup_database():
    print("Setting up database...")
    init_database(seed_defaults=False)
    print("Database structures ready.")

    print()
    print("Checking initial Admin account...")
    from auth.create_admin import create_admin
    create_admin()

    print()
    print("Database setup completed successfully!")


if __name__ == "__main__":
    setup_database()

