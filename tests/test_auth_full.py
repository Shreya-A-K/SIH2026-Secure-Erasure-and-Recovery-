from datetime import datetime, timedelta, timezone

import pytest

from auth.password import hash_password, verify_password
from auth.login import authenticate, unlock_user
from auth.session import login_user, logout, get_current_user
import auth.session as session
from auth.rbac import has_permission
from auth.user_manager import (
    validate_password,
    create_user,
    disable_user,
    enable_user,
    change_role,
    change_password,
)
from database.database import get_connection


# ------------------------------------------------------------
# Test users
# These are separate from the real Admin account.
# ------------------------------------------------------------

TEST_ADMIN_USERNAME = "test_admin"
TEST_ADMIN_PASSWORD = "TestAdmin@123"

TEST_OPERATOR_USERNAME = "test_operator"
TEST_OPERATOR_PASSWORD = "TestOperator@123"

TEST_INVESTIGATOR_USERNAME = "test_investigator"
TEST_INVESTIGATOR_PASSWORD = "TestInvestigator@123"


def ensure_test_user(username, password, role):
    """Create or reset a test user to a known state."""
    connection = get_connection()

    cursor = connection.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    )

    existing_user = cursor.fetchone()

    if existing_user is None:
        connection.execute(
            """
            INSERT INTO users
            (
                username,
                password_hash,
                role,
                is_active,
                failed_attempts,
                locked_until
            )
            VALUES (?, ?, ?, 1, 0, NULL)
            """,
            (
                username,
                hash_password(password),
                role
            )
        )
    else:
        connection.execute(
            """
            UPDATE users
            SET password_hash = ?,
                role = ?,
                is_active = 1,
                failed_attempts = 0,
                locked_until = NULL
            WHERE username = ?
            """,
            (
                hash_password(password),
                role,
                username
            )
        )

    connection.commit()
    connection.close()


def delete_test_users():
    """Delete only users created by this test file."""
    test_usernames = [
        TEST_ADMIN_USERNAME,
        TEST_OPERATOR_USERNAME,
        TEST_INVESTIGATOR_USERNAME,
        "created_by_test",
        "role_change_test",
    ]

    connection = get_connection()

    for username in test_usernames:
        connection.execute(
            "DELETE FROM users WHERE username = ?",
            (username,)
        )

    connection.commit()
    connection.close()


@pytest.fixture(scope="session", autouse=True)
def prepare_test_users():
    """Prepare controlled test users before the test suite."""
    ensure_test_user(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD,
        "ADMIN"
    )

    ensure_test_user(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD,
        "OPERATOR"
    )

    ensure_test_user(
        TEST_INVESTIGATOR_USERNAME,
        TEST_INVESTIGATOR_PASSWORD,
        "INVESTIGATOR"
    )

    yield

    logout()
    delete_test_users()


# ------------------------------------------------------------
# Password tests
# ------------------------------------------------------------

def test_password_hashing():
    password = "Test@1234"

    password_hash = hash_password(password)

    assert password_hash != password
    assert password_hash.startswith("$argon2id$")
    assert verify_password(password, password_hash) is True
    assert verify_password("Wrong@1234", password_hash) is False


def test_password_strength():
    valid, message = validate_password("Test@1234")
    assert valid is True
    assert message == "Password is valid."

    valid, message = validate_password("abc")
    assert valid is False

    valid, message = validate_password("abcdefgh")
    assert valid is False

    valid, message = validate_password("ABCDEFGH")
    assert valid is False

    valid, message = validate_password("Abcdefgh")
    assert valid is False


# ------------------------------------------------------------
# Authentication tests
# ------------------------------------------------------------

def test_admin_login():
    logout()

    user = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert user is not None
    assert user["username"] == TEST_ADMIN_USERNAME
    assert user["role"] == "ADMIN"


def test_wrong_password():
    logout()

    user = authenticate(
        TEST_ADMIN_USERNAME,
        "WrongPassword@123"
    )

    assert user is None


def test_disabled_user_cannot_login():
    ensure_test_user(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD,
        "OPERATOR"
    )

    connection = get_connection()

    connection.execute(
        """
        UPDATE users
        SET is_active = 0
        WHERE username = ?
        """,
        (TEST_OPERATOR_USERNAME,)
    )

    connection.commit()
    connection.close()

    result = authenticate(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD
    )

    assert result is None

    ensure_test_user(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD,
        "OPERATOR"
    )


def test_login_lockout():
    ensure_test_user(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD,
        "OPERATOR"
    )

    logout()

    for _ in range(5):
        result = authenticate(
            TEST_OPERATOR_USERNAME,
            "WrongPassword@123"
        )
        assert result is None

    result = authenticate(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD
    )

    assert result is None

    connection = get_connection()

    cursor = connection.execute(
        """
        SELECT failed_attempts, locked_until
        FROM users
        WHERE username = ?
        """,
        (TEST_OPERATOR_USERNAME,)
    )

    failed_attempts, locked_until = cursor.fetchone()

    connection.close()

    assert failed_attempts >= 5
    assert locked_until is not None

    ensure_test_user(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD,
        "OPERATOR"
    )


def test_admin_unlocks_locked_user():
    ensure_test_user(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD,
        "OPERATOR"
    )

    # Lock the operator account.
    connection = get_connection()

    connection.execute(
        """
        UPDATE users
        SET failed_attempts = 5,
            locked_until = ?
        WHERE username = ?
        """,
        (
            (
                datetime.now(timezone.utc)
                + timedelta(minutes=15)
            ).isoformat(),
            TEST_OPERATOR_USERNAME
        )
    )

    connection.commit()
    connection.close()

    logout()

    admin = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert admin is not None

    login_user(admin)

    result = unlock_user(TEST_OPERATOR_USERNAME)

    assert result is True

    logout()

    operator = authenticate(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD
    )

    assert operator is not None


# ------------------------------------------------------------
# RBAC tests
# ------------------------------------------------------------

def test_rbac_permissions():
    logout()

    # ADMIN
    admin = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert admin is not None
    login_user(admin)

    assert has_permission("DETECT_USB") is True
    assert has_permission("SANITIZE_USB") is True
    assert has_permission("ERASE_FILE") is True
    assert has_permission("RECOVER_FILES") is True
    assert has_permission("VIEW_RECOVERY") is True
    assert has_permission("GENERATE_REPORT") is True
    assert has_permission("VIEW_AUDIT") is True
    assert has_permission("MANAGE_USERS") is True

    logout()

    # OPERATOR
    operator = authenticate(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD
    )

    assert operator is not None
    login_user(operator)

    assert has_permission("DETECT_USB") is True
    assert has_permission("SANITIZE_USB") is True
    assert has_permission("ERASE_FILE") is True

    assert has_permission("RECOVER_FILES") is False
    assert has_permission("VIEW_RECOVERY") is False
    assert has_permission("GENERATE_REPORT") is False
    assert has_permission("VIEW_AUDIT") is False
    assert has_permission("MANAGE_USERS") is False

    logout()

    # INVESTIGATOR
    investigator = authenticate(
        TEST_INVESTIGATOR_USERNAME,
        TEST_INVESTIGATOR_PASSWORD
    )

    assert investigator is not None
    login_user(investigator)

    assert has_permission("DETECT_USB") is True
    assert has_permission("RECOVER_FILES") is True
    assert has_permission("VIEW_RECOVERY") is True
    assert has_permission("GENERATE_REPORT") is True
    assert has_permission("VIEW_AUDIT") is True

    assert has_permission("SANITIZE_USB") is False
    assert has_permission("ERASE_FILE") is False
    assert has_permission("MANAGE_USERS") is False

    logout()


def test_logged_out_permissions():
    logout()

    assert has_permission("DETECT_USB") is False
    assert has_permission("MANAGE_USERS") is False
    assert has_permission("SANITIZE_USB") is False
    assert has_permission("RECOVER_FILES") is False
    assert has_permission("VIEW_AUDIT") is False


# ------------------------------------------------------------
# Session tests
# ------------------------------------------------------------

def test_session_login_logout():
    logout()

    user = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert user is not None

    login_user(user)

    current_user = get_current_user()

    assert current_user is not None
    assert current_user["username"] == TEST_ADMIN_USERNAME

    logout()

    assert get_current_user() is None


def test_session_timeout():
    logout()

    user = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert user is not None

    login_user(user)

    assert get_current_user() is not None

    # Simulate 16 minutes without activity.
    session._last_activity = (
        datetime.now(timezone.utc)
        - timedelta(minutes=16)
    )

    assert get_current_user() is None

    logout()


def test_session_activity_refreshes_timeout():
    logout()

    user = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert user is not None

    login_user(user)

    # Simulate last activity 10 minutes ago.
    session._last_activity = (
        datetime.now(timezone.utc)
        - timedelta(minutes=10)
    )

    old_activity = session._last_activity

    # Accessing the session counts as activity.
    assert get_current_user() is not None

    new_activity = session._last_activity

    assert new_activity > old_activity

    logout()


# ------------------------------------------------------------
# User-management tests
# ------------------------------------------------------------

def test_operator_cannot_manage_users():
    logout()

    operator = authenticate(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD
    )

    assert operator is not None
    login_user(operator)

    result, message = create_user(
        "created_by_test",
        "TestUser@123",
        "OPERATOR"
    )

    assert result is False
    assert message == "Access denied. Admin permission required."

    logout()


def test_admin_can_create_user():
    logout()

    admin = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert admin is not None
    login_user(admin)

    result, message = create_user(
        "created_by_test",
        "TestUser@123",
        "OPERATOR"
    )

    assert result is True
    assert message == "User created successfully!"

    logout()

    connection = get_connection()

    cursor = connection.execute(
        """
        SELECT username, role, is_active
        FROM users
        WHERE username = ?
        """,
        ("created_by_test",)
    )

    created_user = cursor.fetchone()

    connection.close()

    assert created_user is not None
    assert created_user[0] == "created_by_test"
    assert created_user[1] == "OPERATOR"
    assert created_user[2] == 1


def test_admin_can_change_role():
    logout()

    admin = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert admin is not None
    login_user(admin)

    result, message = create_user(
        "role_change_test",
        "RoleTest@123",
        "OPERATOR"
    )

    assert result is True

    result, message = change_role(
        "role_change_test",
        "INVESTIGATOR"
    )

    assert result is True
    assert message == "Role changed successfully."

    logout()

    connection = get_connection()

    cursor = connection.execute(
        """
        SELECT role
        FROM users
        WHERE username = ?
        """,
        ("role_change_test",)
    )

    user_data = cursor.fetchone()

    connection.close()

    assert user_data is not None
    assert user_data[0] == "INVESTIGATOR"


def test_admin_can_disable_and_enable_user():
    ensure_test_user(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD,
        "OPERATOR"
    )

    logout()

    admin = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert admin is not None
    login_user(admin)

    result, message = disable_user(
        TEST_OPERATOR_USERNAME
    )

    assert result is True
    assert message == "User disabled successfully."

    logout()

    # Disabled user cannot log in.
    result = authenticate(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD
    )

    assert result is None

    # Admin enables the user again.
    admin = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert admin is not None
    login_user(admin)

    result, message = enable_user(
        TEST_OPERATOR_USERNAME
    )

    assert result is True
    assert message == "User enabled successfully."

    logout()

    # Enabled user can log in again.
    result = authenticate(
        TEST_OPERATOR_USERNAME,
        TEST_OPERATOR_PASSWORD
    )

    assert result is not None


def test_cannot_disable_last_active_admin():
    logout()

    conn = get_connection()
    other_admins = conn.execute(
        "SELECT username FROM users WHERE role = 'ADMIN' AND is_active = 1 AND username != ?",
        (TEST_ADMIN_USERNAME,)
    ).fetchall()
    conn.execute(
        "UPDATE users SET is_active = 0 WHERE role = 'ADMIN' AND username != ?",
        (TEST_ADMIN_USERNAME,)
    )
    conn.commit()
    conn.close()

    try:
        admin = authenticate(
            TEST_ADMIN_USERNAME,
            TEST_ADMIN_PASSWORD
        )

        assert admin is not None
        login_user(admin)

        result, message = disable_user(
            TEST_ADMIN_USERNAME
        )

        assert result is False
        assert message == "Cannot disable the last active Admin."

        logout()
    finally:
        conn = get_connection()
        for row in other_admins:
            conn.execute("UPDATE users SET is_active = 1 WHERE username = ?", (row[0],))
        conn.commit()
        conn.close()


def test_password_change():
    logout()

    user = authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
    )

    assert user is not None
    login_user(user)

    result, message = change_password(
        TEST_ADMIN_PASSWORD,
        "TestAdmin@456"
    )

    assert result is True
    assert message == "Password changed successfully."

    logout()

    # New password must work.
    user = authenticate(
        TEST_ADMIN_USERNAME,
        "TestAdmin@456"
    )

    assert user is not None
    login_user(user)

    # Restore the original test password.
    result, message = change_password(
        "TestAdmin@456",
        TEST_ADMIN_PASSWORD
    )

    assert result is True
    assert message == "Password changed successfully."

    logout()

