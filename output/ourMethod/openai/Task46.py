import base64
import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Dict, Tuple, Optional


@dataclass(frozen=True)
class UserRecord:
    name: str
    email_lower: str
    password_hash_b64: str
    salt_b64: str
    iterations: int


class InMemoryDatabase:
    def __init__(self) -> None:
        self._users: Dict[str, UserRecord] = {}

    def email_exists(self, email_lower: str) -> bool:
        return email_lower in self._users

    def add_user(self, user: UserRecord) -> bool:
        if user.email_lower in self._users:
            return False
        self._users[user.email_lower] = user
        return True

    def size(self) -> int:
        return len(self._users)


class PasswordHasher:
    SALT_LEN = 16
    ITERATIONS = 210_000
    KEY_LEN = 32  # 256-bit

    @staticmethod
    def hash_password(password: str) -> Tuple[str, str, int]:
        if password is None:
            raise ValueError("password is required")
        salt = secrets.token_bytes(PasswordHasher.SALT_LEN)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PasswordHasher.ITERATIONS, dklen=PasswordHasher.KEY_LEN)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        hash_b64 = base64.b64encode(dk).decode("ascii")
        return hash_b64, salt_b64, PasswordHasher.ITERATIONS


class Validator:
    EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
    NAME_RE = re.compile(r"^[A-Za-z][A-Za-z '\-]{0,99}$")

    @staticmethod
    def validate_name(name: Optional[str]) -> Optional[str]:
        if name is None:
            return "Name is required."
        trimmed = name.strip()
        if not trimmed:
            return "Name cannot be empty."
        if len(trimmed) > 100:
            return "Name is too long."
        if not Validator.NAME_RE.match(trimmed):
            return "Name contains invalid characters."
        return None

    @staticmethod
    def validate_email(email: Optional[str]) -> Optional[str]:
        if email is None:
            return "Email is required."
        trimmed = email.strip()
        if len(trimmed) > 254:
            return "Email is too long."
        if not Validator.EMAIL_RE.match(trimmed):
            return "Email is invalid."
        return None

    @staticmethod
    def validate_password(password: Optional[str]) -> Optional[str]:
        if password is None:
            return "Password is required."
        if len(password) < 12:
            return "Password must be at least 12 characters."
        if len(password) > 128:
            return "Password is too long."
        if " " in password:
            return "Password must not contain spaces."
        if not re.search(r"[A-Z]", password):
            return "Password must include an uppercase letter."
        if not re.search(r"[a-z]", password):
            return "Password must include a lowercase letter."
        if not re.search(r"[0-9]", password):
            return "Password must include a digit."
        if not re.search(r"[^A-Za-z0-9]", password):
            return "Password must include a special character."
        return None


class RegistrationService:
    def __init__(self, db: InMemoryDatabase) -> None:
        self.db = db

    def register(self, name: str, email: str, password: str) -> Tuple[bool, str]:
        err = Validator.validate_name(name)
        if err:
            return False, err
        err = Validator.validate_email(email)
        if err:
            return False, err
        err = Validator.validate_password(password)
        if err:
            return False, err

        email_lower = email.strip().lower()
        if self.db.email_exists(email_lower):
            return False, "An account with this email already exists."

        try:
            hash_b64, salt_b64, iters = PasswordHasher.hash_password(password)
            user = UserRecord(
                name=name.strip(),
                email_lower=email_lower,
                password_hash_b64=hash_b64,
                salt_b64=salt_b64,
                iterations=iters,
            )
            if not self.db.add_user(user):
                return False, "Registration failed due to a concurrent duplicate email."
            return True, "Registration successful."
        except Exception:
            return False, "Internal error during registration."


def main() -> None:
    db = InMemoryDatabase()
    service = RegistrationService(db)

    tests = [
        ("Alice Johnson", "alice@example.com", "Str0ng!Password#1"),
        ("Bob O'Hara".replace("'", ""), "bob.ohara@example.org", "An0ther$ecurePass!"),
        ("Alice J.", "alice@example.com", "NewStrong!Passw0rd"),
        ("Charlie Brown", "invalid-email@", "ValidPassw0rd!@#"),
        ("Dana White", "dana.white@example.net", "weakpass"),
    ]

    for idx, (n, e, p) in enumerate(tests, start=1):
        ok, msg = service.register(n, e, p)
        print(f"TC{idx}: {'SUCCESS' if ok else 'ERROR'} - {msg}")


if __name__ == "__main__":
    main()