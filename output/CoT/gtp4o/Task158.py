# Chain-of-Through process in code generation:
# 1) Problem understanding: Safely use user input in an OS command. We'll run "ping" with a provided host.
# 2) Security requirements: Avoid shell=True, strictly validate inputs, set timeouts, and limit output size.
# 3) Secure coding generation: Use subprocess.run with argument array, regex validation, platform-specific args.
# 4) Code review: Ensure no shell use, strict validation, timeout, and safe output handling.
# 5) Secure code output: Final secure implementation below.

import platform
import re
import subprocess
from typing import Tuple

_HOSTNAME_RE = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
_IPV4_RE = re.compile(r'^((25[0-5]|2[0-4]\d|1?\d?\d)(\.|$)){4}$')

def _is_valid_host_or_ipv4(host: str) -> bool:
    if host is None:
        return False
    h = host.strip()
    if not h or len(h) > 253:
        return False
    # allowlist chars only
    for c in h:
        if not (c.isalnum() or c in "-."):
            return False
    return bool(_HOSTNAME_RE.match(h)) or bool(_IPV4_RE.match(h))

def safe_ping(host: str, timeout_sec: float = 3.0) -> Tuple[int, str]:
    """
    Safely runs ping for a single echo request to the given host.
    Returns (exit_code, output).
    """
    if not _is_valid_host_or_ipv4(host):
        return (1, "Invalid host input rejected.")
    is_windows = platform.system().lower().startswith('win')
    if is_windows:
        # ping -n 1 -w <ms>
        ms = int(min(max(timeout_sec * 1000, 500), 10000))
        cmd = ["ping", "-n", "1", "-w", str(ms), host]
    else:
        # ping -c 1 -W <sec>
        sec = int(min(max(int(timeout_sec), 1), 10))
        cmd = ["ping", "-c", "1", "-W", str(sec), host]
    try:
        # No shell; capture output; enforce timeout.
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec+1.0)
        out = (cp.stdout + cp.stderr).strip()
        if len(out) > 65536:
            out = out[:65536] + "...[truncated]"
        return (cp.returncode, out if out else f"Exit={cp.returncode} (no output)")
    except subprocess.TimeoutExpired:
        return (124, "Command timed out.")
    except Exception as e:
        return (1, f"Execution error: {str(e)}")

if __name__ == "__main__":
    tests = [
        "localhost",
        "127.0.0.1",
        "example.com",
        "invalid host",  # should be rejected
        "8.8.8.8",
    ]
    for t in tests:
        code, out = safe_ping(t, 3.0)
        print(f"Test host: {t}")
        print(out)
        print("----")