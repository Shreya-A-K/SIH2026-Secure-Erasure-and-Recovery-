from datetime import datetime, timedelta, timezone


SESSION_TIMEOUT_MINUTES = 15

_current_user = None
_last_activity = None


def login_user(user):
    global _current_user, _last_activity

    _current_user = user
    _last_activity = datetime.now(timezone.utc)


def logout():
    global _current_user, _last_activity

    _current_user = None
    _last_activity = None


def get_current_user():
    global _current_user, _last_activity

    if _current_user is None:
        return None

    current_time = datetime.now(timezone.utc)

    # Check whether 15 minutes have passed since last activity
    if current_time - _last_activity > timedelta(
        minutes=SESSION_TIMEOUT_MINUTES
    ):
        logout()
        return None

    # User is still active → reset the timer
    _last_activity = current_time

    return _current_user
