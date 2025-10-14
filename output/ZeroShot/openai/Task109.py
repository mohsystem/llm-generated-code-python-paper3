import re

MAX_USERNAME_LEN = 32
MIN_USERNAME_LEN = 3
MAX_EMAIL_LEN = 320
MAX_PHONE_LEN = 16
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
MAX_ZIP_LEN = 10

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,16}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9_%+.-]+(\.[A-Za-z0-9_%+.-]+)*@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}$")
PHONE_E164_RE = re.compile(r"^\+[1-9][0-9]{1,14}$")
ZIP_US_RE = re.compile(r"^[0-9]{5}(-[0-9]{4})?$")
P_UPPER = re.compile(r"[A-Z]")
P_LOWER = re.compile(r"[a-z]")
P_DIGIT = re.compile(r"[0-9]")
P_SPECIAL = re.compile(r"[^A-Za-z0-9]")

def _safe_fullmatch(pattern: re.Pattern, s: str, max_len: int) -> bool:
    if s is None:
        return False
    if len(s) > max_len:
        return False
    return pattern.fullmatch(s) is not None

def validate_username(username: str) -> bool:
    if username is None:
        return False
    if not (MIN_USERNAME_LEN <= len(username) <= MAX_USERNAME_LEN):
        return False
    return _safe_fullmatch(USERNAME_RE, username, MAX_USERNAME_LEN)

def validate_email(email: str) -> bool:
    if email is None:
        return False
    if len(email) > MAX_EMAIL_LEN:
        return False
    return _safe_fullmatch(EMAIL_RE, email, MAX_EMAIL_LEN)

def validate_phone_e164(phone: str) -> bool:
    if phone is None:
        return False
    return _safe_fullmatch(PHONE_E164_RE, phone, MAX_PHONE_LEN)

def validate_password(password: str) -> bool:
    if password is None:
        return False
    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        return False
    if not P_UPPER.search(password):
        return False
    if not P_LOWER.search(password):
        return False
    if not P_DIGIT.search(password):
        return False
    if not P_SPECIAL.search(password):
        return False
    return True

def validate_us_zip(zip_code: str) -> bool:
    if zip_code is None:
        return False
    return _safe_fullmatch(ZIP_US_RE, zip_code, MAX_ZIP_LEN)

if __name__ == "__main__":
    # 5 test cases
    print(validate_username("user_name12"))            # True
    print(validate_email("john.doe@example.co.uk"))    # True
    print(validate_phone_e164("+14155552671"))         # True
    print(validate_password("Str0ng!Pass"))            # True
    print(validate_us_zip("12345-6789"))               # True