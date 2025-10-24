import os
import re
import time
import hmac
import hashlib
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class PasswordHistoryEntry:
    salt: bytes
    hash: bytes
    iterations: int
    set_at: datetime


@dataclass
class UserRecord:
    username: str
    password_hash: bytes
    salt: bytes
    iterations: int
    pw_set_at: datetime
    pw_expires_at: datetime
    history: List[PasswordHistoryEntry] = field(default_factory=list)


@dataclass
class SessionRecord:
    username: str
    issued_at: datetime
    last_access_at: datetime
    expires_at: datetime
    token_hash_hex: str


class PasswordPolicy:
    def __init__(self, min_len: int = 12, max_len: int = 128) -> None:
        self.min_len = max(8, min_len)
        self.max_len = max(self.min_len, max_len)
        self._common = {
            "password",
            "123456",
            "qwerty",
            "letmein",
            "admin",
            "welcome",
            "iloveyou",
            "monkey",
            "abc123",
            "12345678",
        }

    def validate(self, username: str, password: str) -> Tuple[bool, str]:
        if not isinstance(password, str):
            return False, "Invalid password type."
        if not isinstance(username, str):
            return False, "Invalid username type."
        if len(password) < self.min_len or len(password) > self.max_len:
            return False, "Password length out of allowed range."
        if any(c.isspace() for c in password):
            return False, "Password must not contain whitespace."
        lower = any(c.islower() for c in password)
        upper = any(c.isupper() for c in password)
        digit = any(c.isdigit() for c in password)
        special = any(not c.isalnum() for c in password)
        if not (lower and upper and digit and special):
            return False, "Password must include lowercase, uppercase, digit, and special char."
        if password.lower() in self._common:
            return False, "Password is too common."
        uname = username.lower()
        if uname and uname in password.lower():
            return False, "Password must not contain the username."
        # Reject 3+ repeated characters
        if re.search(r"(.)\1\1", password):
            return False, "Password has excessive repeated characters."
        return True, ""


class SessionManager:
    def __init__(self, session_ttl_secs: int = 1800, password_expiry_days: int = 90, iterations: int = 200_000) -> None:
        self._users: Dict[str, UserRecord] = {}
        self._sessions: Dict[str, SessionRecord] = {}
        self._lock = threading.RLock()
        self._policy = PasswordPolicy()
        self._session_ttl = max(1, min(7 * 24 * 3600, int(session_ttl_secs)))
        self._pw_expiry_days = max(1, min(3650, int(password_expiry_days)))
        self._iterations = max(100_000, min(1_000_000, int(iterations)))
        self._token_hmac_key = self._load_token_hmac_key()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _gen_salt(n: int = 16) -> bytes:
        n = max(16, min(64, int(n)))
        return secrets.token_bytes(n)

    def _hash_password(self, password: str, salt: bytes, iterations: int) -> bytes:
        if not isinstance(password, str) or not isinstance(salt, (bytes, bytearray)):
            raise ValueError("Invalid types for hashing.")
        if len(salt) < 16 or iterations < 100_000 or iterations > 1_000_000:
            raise ValueError("Invalid salt or iteration count.")
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)

    def _load_token_hmac_key(self) -> bytes:
        key_env = os.getenv("SESSION_HMAC_KEY")
        if key_env and isinstance(key_env, str) and 8 <= len(key_env) <= 256:
            # Derive fixed-length key from provided secret using SHA-256
            return hashlib.sha256(key_env.encode("utf-8")).digest()
        # Fallback to ephemeral key if env not set
        return secrets.token_bytes(32)

    def _token_hash_hex(self, token: str) -> str:
        mac = hmac.new(self._token_hmac_key, token.encode("utf-8"), hashlib.sha256)
        return mac.hexdigest()

    @staticmethod
    def _valid_username(username: str) -> bool:
        if not isinstance(username, str):
            return False
        if len(username) < 3 or len(username) > 32:
            return False
        return re.fullmatch(r"[a-zA-Z0-9_.-]+", username) is not None

    def _cleanup_expired_sessions(self) -> None:
        now = self._now()
        to_delete = [k for k, s in self._sessions.items() if s.expires_at <= now]
        for k in to_delete:
            del self._sessions[k]

    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        if not self._valid_username(username):
            return False, "Invalid username format."
        ok, msg = self._policy.validate(username, password)
        if not ok:
            return False, msg
        with self._lock:
            if username.lower() in (u.lower() for u in self._users.keys()):
                return False, "Username already exists."
            salt = self._gen_salt()
            pw_hash = self._hash_password(password, salt, self._iterations)
            now = self._now()
            user = UserRecord(
                username=username,
                password_hash=pw_hash,
                salt=salt,
                iterations=self._iterations,
                pw_set_at=now,
                pw_expires_at=now + timedelta(days=self._pw_expiry_days),
                history=[PasswordHistoryEntry(salt=salt, hash=pw_hash, iterations=self._iterations, set_at=now)],
            )
            self._users[username] = user
        return True, ""

    def authenticate(self, username: str, password: str) -> Optional[str]:
        if not isinstance(username, str) or not isinstance(password, str):
            return None
        with self._lock:
            user = self._users.get(username)
            if user is None:
                return None
            try:
                attempt_hash = self._hash_password(password, user.salt, user.iterations)
            except Exception:
                return None
            if not hmac.compare_digest(attempt_hash, user.password_hash):
                return None
            if self._now() >= user.pw_expires_at:
                return None
            # Generate session token
            token = secrets.token_urlsafe(32)
            th = self._token_hash_hex(token)
            now = self._now()
            sess = SessionRecord(
                username=username,
                issued_at=now,
                last_access_at=now,
                expires_at=now + timedelta(seconds=self._session_ttl),
                token_hash_hex=th,
            )
            self._sessions[th] = sess
            return token

    def validate_session(self, token: str) -> Optional[str]:
        if not isinstance(token, str) or not (16 <= len(token) <= 256):
            return None
        th = self._token_hash_hex(token)
        with self._lock:
            self._cleanup_expired_sessions()
            sess = self._sessions.get(th)
            if sess is None:
                return None
            now = self._now()
            if now >= sess.expires_at:
                del self._sessions[th]
                return None
            # Update last access; no sliding extension by default
            sess.last_access_at = now
            return sess.username

    def logout(self, token: str) -> bool:
        if not isinstance(token, str) or not (16 <= len(token) <= 256):
            return False
        th = self._token_hash_hex(token)
        with self._lock:
            return self._sessions.pop(th, None) is not None

    def logout_user_all_sessions(self, username: str) -> int:
        if not isinstance(username, str):
            return 0
        with self._lock:
            keys = [k for k, s in self._sessions.items() if s.username == username]
            for k in keys:
                del self._sessions[k]
            return len(keys)

    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        if not isinstance(username, str) or not isinstance(old_password, str) or not isinstance(new_password, str):
            return False, "Invalid input types."
        ok, msg = self._policy.validate(username, new_password)
        if not ok:
            return False, msg
        with self._lock:
            user = self._users.get(username)
            if user is None:
                return False, "User not found."
            try:
                old_hash = self._hash_password(old_password, user.salt, user.iterations)
            except Exception:
                return False, "Authentication failed."
            if not hmac.compare_digest(old_hash, user.password_hash):
                return False, "Authentication failed."
            # Prevent reuse of recent passwords (last 5)
            history_to_check = user.history[-5:]
            for entry in history_to_check:
                try:
                    candidate = self._hash_password(new_password, entry.salt, entry.iterations)
                except Exception:
                    return False, "Internal error."
                if hmac.compare_digest(candidate, entry.hash):
                    return False, "New password must not reuse a recent password."
            # Set new password
            new_salt = self._gen_salt()
            new_hash = self._hash_password(new_password, new_salt, self._iterations)
            now = self._now()
            user.salt = new_salt
            user.password_hash = new_hash
            user.iterations = self._iterations
            user.pw_set_at = now
            user.pw_expires_at = now + timedelta(days=self._pw_expiry_days)
            user.history.append(PasswordHistoryEntry(salt=new_salt, hash=new_hash, iterations=self._iterations, set_at=now))
            # Limit history size
            if len(user.history) > 10:
                user.history = user.history[-10:]
            # Invalidate all sessions for this user
            self.logout_user_all_sessions(username)
            return True, ""

    # Helper for testing: count active sessions for a user
    def active_sessions_count(self, username: str) -> int:
        with self._lock:
            self._cleanup_expired_sessions()
            return sum(1 for s in self._sessions.values() if s.username == username)


def run_tests() -> None:
    print("Test 1: Register and login basic flow")
    mgr = SessionManager(session_ttl_secs=600, password_expiry_days=90)
    ok, msg = mgr.register_user("alice", "Str0ng!Passw0rd#1")
    print(" - registration ok:", ok)
    token = mgr.authenticate("alice", "Str0ng!Passw0rd#1")
    print(" - authentication ok:", token is not None)
    uname = mgr.validate_session(token if token else "")
    print(" - session valid:", uname == "alice")

    print("Test 2: Wrong password rejected")
    bad_token = mgr.authenticate("alice", "Wrong!Passw0rd")
    print(" - bad authentication rejected:", bad_token is None)

    print("Test 3: Session expiration")
    mgr2 = SessionManager(session_ttl_secs=1, password_expiry_days=90)
    ok2, _ = mgr2.register_user("bob", "An0ther$trongPwd!")
    t2 = mgr2.authenticate("bob", "An0ther$trongPwd!")
    time.sleep(1.5)
    v2 = mgr2.validate_session(t2 if t2 else "")
    print(" - expired session invalid:", v2 is None)

    print("Test 4: Password change invalidates sessions and allows new login")
    mgr3 = SessionManager()
    ok3, _ = mgr3.register_user("carol", "Sup3r$ecurePwd!")
    t3 = mgr3.authenticate("carol", "Sup3r$ecurePwd!")
    changed, _ = mgr3.change_password("carol", "Sup3r$ecurePwd!", "N3w$ecurePwd!123")
    still_valid = mgr3.validate_session(t3 if t3 else "") is not None
    t3new = mgr3.authenticate("carol", "N3w$ecurePwd!123")
    print(" - change success:", changed)
    print(" - old session invalidated:", not still_valid)
    print(" - new login ok:", t3new is not None)

    print("Test 5: Weak password rejected")
    mgr4 = SessionManager()
    ok4a, msg4a = mgr4.register_user("dave", "password")
    ok4b, msg4b = mgr4.register_user("eve", "short1!")
    ok4c, msg4c = mgr4.register_user("mallory", "NoDigits!!!!!!!!!")
    print(" - weak 'password' rejected:", not ok4a)
    print(" - too short rejected:", not ok4b)
    print(" - missing digits rejected:", not ok4c)


if __name__ == "__main__":
    run_tests()