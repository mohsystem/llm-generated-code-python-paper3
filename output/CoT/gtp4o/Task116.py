# Chain-of-Through Process in Code (Python)
# 1) Problem understanding:
#    - Implement a secure function to change a user's password using 'chpasswd' (when running as root), then drop privileges to a non-root user.
# 2) Security requirements:
#    - Validate username and password.
#    - Avoid command-line exposure of secrets (write to stdin).
#    - Minimal environment and no shell invocation.
#    - Drop supplementary groups, then gid, then uid.
#    - Zero out sensitive buffers where possible.
# 3) Secure coding generation: careful subprocess usage, robust validation and error handling.
# 4) Code review: no secret logging, safe patterns, return codes.
# 5) Secure code output: final function and tests below.

import os
import re
import subprocess
from typing import Optional

_USERNAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')

def _is_valid_username(u: str) -> bool:
    return bool(u and _USERNAME_RE.match(u))

def _is_valid_password(pw: str) -> bool:
    if pw is None:
        return False
    if len(pw) < 8 or len(pw) > 128:
        return False
    if ':' in pw:
        return False
    for ch in pw:
        oc = ord(ch)
        if oc < 0x20 or oc > 0x7E:
            return False
    return True

def _find_chpasswd() -> Optional[str]:
    for p in ("/usr/sbin/chpasswd", "/usr/bin/chpasswd", "/sbin/chpasswd", "/bin/chpasswd"):
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    return None

def _minimal_env():
    return {"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C"}

def _secure_zero_bytearray(b: bytearray):
    for i in range(len(b)):
        b[i] = 0

def _run_chpasswd(username: str, password: str) -> int:
    chpasswd = _find_chpasswd()
    if not chpasswd:
        return -2
    # Prepare payload as bytes to allow zeroing
    payload = bytearray(f"{username}:{password}\n".encode("ascii", "strict"))
    try:
        proc = subprocess.Popen(
            [chpasswd],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=_minimal_env(),
            close_fds=True
        )
        assert proc.stdin is not None
        proc.stdin.write(payload)
        proc.stdin.flush()
        proc.stdin.close()
        # Drain output
        if proc.stdout:
            try:
                for _ in proc.stdout:
                    pass
            finally:
                proc.stdout.close()
        rc = proc.wait()
        return rc
    finally:
        _secure_zero_bytearray(payload)

def _drop_privileges(to_uid: Optional[int]=None, to_gid: Optional[int]=None) -> bool:
    try:
        euid = os.geteuid()
        ruid = os.getuid()
        egid = os.getegid()
        rgid = os.getgid()

        target_uid = ruid if to_uid is None else to_uid
        target_gid = rgid if to_gid is None else to_gid

        if euid != 0:
            return True  # nothing to do

        # Clear supplementary groups
        try:
            os.setgroups([])
        except Exception:
            pass

        # Prefer setresgid/setresuid if available
        if hasattr(os, "setresgid"):
            os.setresgid(target_gid, target_gid, target_gid)
        else:
            os.setgid(target_gid)

        if hasattr(os, "setresuid"):
            os.setresuid(target_uid, target_uid, target_uid)
        else:
            os.setuid(target_uid)

        # Verify
        return os.geteuid() == target_uid and os.getegid() == target_gid
    except Exception:
        return False

def change_password_and_drop(username: str, new_password: str, dry_run: bool=True, drop_to_uid: Optional[int]=None, drop_to_gid: Optional[int]=None) -> int:
    if not _is_valid_username(username):
        return -1
    if not _is_valid_password(new_password):
        return -2

    rc = 0
    try:
        if not dry_run and os.geteuid() == 0:
            rc = _run_chpasswd(username, new_password)
            if rc != 0:
                return -3 if rc == -2 else rc
        # Drop privileges after operation if possible
        _drop_privileges(drop_to_uid, drop_to_gid)
        return rc
    finally:
        # Attempt to clear sensitive data reference
        # Python strings are immutable; cannot zero in-place. We remove references.
        new_password = None

if __name__ == "__main__":
    # 5 test cases, all dry-run
    tests = [
        ("alice", "S3curePwd1!"),
        ("bob", "AnotherPwd2#"),
        ("charlie", "ThirdPwd3$"),
        ("dave-user", "FourthPwd4%"),
        ("eve_user", "FifthPwd5^"),
    ]
    for i, (u, p) in enumerate(tests, 1):
        rc = change_password_and_drop(u, p, dry_run=True)
        print(f"Test {i} user={u} rc={rc}")