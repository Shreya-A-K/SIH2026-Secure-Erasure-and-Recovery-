from pathlib import Path
import sqlite3


# Get the main project folder
BASE_DIR = Path(__file__).resolve().parent.parent

# Database will always be inside project/data/
DATABASE_NAME = BASE_DIR / "data" / "forensic.db"


def get_connection():
    DATABASE_NAME.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_NAME)
    return connection

def create_users_table():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()
def add_login_security_columns():
    connection = get_connection()

    try:
        connection.execute(
            "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0"
        )
    except sqlite3.OperationalError:
        pass

    try:
        connection.execute(
            "ALTER TABLE users ADD COLUMN locked_until TIMESTAMP"
        )
    except sqlite3.OperationalError:
        pass

    connection.commit()
    connection.close()
def create_rbac_tables():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS role_permissions (
            role TEXT NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY (role, permission_id),
            FOREIGN KEY (permission_id) REFERENCES permissions(id)
        )
    """)

    connection.commit()
    connection.close()
def create_permissions():
    connection = get_connection()

    permissions = [
        "DETECT_USB",
        "SANITIZE_USB",
        "ERASE_FILE",
        "RECOVER_FILES",
        "VIEW_RECOVERY",
        "GENERATE_REPORT",
        "VIEW_AUDIT",
        "MANAGE_USERS"
    ]

    for permission in permissions:
        connection.execute(
            """
            INSERT OR IGNORE INTO permissions (name)
            VALUES (?)
            """,
            (permission,)
        )

    connection.commit()
    connection.close()

    print("Permissions created successfully!")
def create_role_permissions():
    connection = get_connection()

    role_permissions = {
        "ADMIN": [
            "DETECT_USB",
            "SANITIZE_USB",
            "ERASE_FILE",
            "RECOVER_FILES",
            "VIEW_RECOVERY",
            "GENERATE_REPORT",
            "VIEW_AUDIT",
            "MANAGE_USERS"
        ],

        "OPERATOR": [
            "DETECT_USB",
            "SANITIZE_USB",
            "ERASE_FILE"
        ],

        "INVESTIGATOR": [
            "DETECT_USB",
            "RECOVER_FILES",
            "VIEW_RECOVERY",
            "GENERATE_REPORT",
            "VIEW_AUDIT"
        ]
    }

    for role, permissions in role_permissions.items():

        for permission in permissions:

            cursor = connection.execute(
                "SELECT id FROM permissions WHERE name = ?",
                (permission,)
            )

            result = cursor.fetchone()

            if result:
                permission_id = result[0]

                connection.execute(
                    """
                    INSERT OR IGNORE INTO role_permissions
                    (role, permission_id)
                    VALUES (?, ?)
                    """,
                    (role, permission_id)
                )

    connection.commit()
    connection.close()

    print("Role permissions created successfully!")
