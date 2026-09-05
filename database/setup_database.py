from database.database import (
    create_users_table,
    add_login_security_columns,
    create_rbac_tables,
    create_permissions,
    create_role_permissions
)

from auth.create_admin import create_admin


def setup_database():
    print("Setting up database...")

    create_users_table()
    print("Users table ready.")

    add_login_security_columns()
    print("Login security columns ready.")

    create_rbac_tables()
    print("RBAC tables ready.")

    create_permissions()
    print("Permissions ready.")

    create_role_permissions()
    print("Role permissions ready.")

    print()
    print("Checking initial Admin account...")

    create_admin()

    print()
    print("Database setup completed successfully!")


if __name__ == "__main__":
    setup_database()
