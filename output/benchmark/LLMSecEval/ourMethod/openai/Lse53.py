from typing import Final

LOGIN_PATH: Final[str] = "/login"
USER_PATH: Final[str] = "/user"
ADMIN_PATH: Final[str] = "/admin"

def get_redirect_target(is_logged_in: bool, is_admin: bool) -> str:
    if not isinstance(is_logged_in, bool) or not isinstance(is_admin, bool):
        raise ValueError("Invalid input")
    if not is_logged_in:
        return LOGIN_PATH
    if is_admin:
        return ADMIN_PATH
    return USER_PATH

def _run_test(is_logged_in, is_admin) -> None:
    try:
        result = get_redirect_target(is_logged_in, is_admin)
        print(f"is_logged_in={is_logged_in}, is_admin={is_admin} -> {result}")
    except Exception as e:
        print(f"is_logged_in={is_logged_in}, is_admin={is_admin} -> error")

if __name__ == "__main__":
    # 5 test cases
    _run_test(False, False)  # /login
    _run_test(True, False)   # /user
    _run_test(True, True)    # /admin
    _run_test(False, True)   # /login
    _run_test(True, True)    # /admin