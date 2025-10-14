import os
import re
import pwd
import grp
import shutil
import subprocess
from typing import Optional

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

def _is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if not USERNAME_RE.fullmatch(username):
        return False
    try:
        pwd.getpwnam(username)
    except KeyError:
        return False
    return True

def _is_strong_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) < 8 or len(password) > 128:
        return False
    return True

def _find_chpasswd_path() -> Optional[str]:
    candidates = ["/usr/sbin/chpasswd", "/sbin/chpasswd", "/usr/bin/chpasswd", "/bin/chpasswd"]
    for p in candidates:
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    p = shutil.which("chpasswd")
    return p

def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def _secure_clear_bytes(b: bytearray):
    for i in range(len(b)):
        b[i] = 0

def change_password_and_drop(username: str, new_password: str, drop_to_user: str = "nobody", dry_run: bool = True) -> bool:
    if not _is_valid_username(username):
        return False
    if not _is_strong_password(new_password):
        return False

    chpasswd_path = _find_chpasswd_path()
    if not dry_run:
        if not _is_root():
            return False
        if not chpasswd_path:
            return False
        # Use stdin to avoid exposing password via process arguments
        data = f"{username}:{new_password}\n".encode("utf-8")
        try:
            env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
            res = subprocess.run([chpasswd_path], input=data, env=env, check=False, capture_output=True)
            ok = (res.returncode == 0)
            if not ok:
                return False
        finally:
            # Attempt to clear sensitive data from memory
            try:
                ba = bytearray(data)
                _secure_clear_bytes(ba)
            except Exception:
                pass

    # Drop privileges after privileged operation
    try:
        if _is_root():
            # Resolve drop user
            if not drop_to_user:
                drop_to_user = "nobody"
            pw = pwd.getpwnam(drop_to_user)
            os.initgroups(pw.pw_name, pw.pw_gid)
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            # Confirm drop
            if os.geteuid() == 0 or os.getuid() == 0:
                return False
    except Exception:
        # If not root, privilege drop is not applicable; treat as non-fatal
        if _is_root():
            return False

    return True

if __name__ == "__main__":
    # 5 test cases (dry-run to avoid real password changes)
    print(change_password_and_drop("testuser", "CorrectHorse1!", "nobody", True))
    print(change_password_and_drop("root", "XyZ12345!", "nobody", True))
    print(change_password_and_drop("bad:user", "StrongPassw0rd!", "nobody", True))
    print(change_password_and_drop("good_user", "short", "nobody", True))
    print(change_password_and_drop("alice", "Secur3P@ssword!", "nobody", True))