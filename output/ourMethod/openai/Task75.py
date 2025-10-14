import os
import sys
from typing import Optional

# Return codes:
# 0 = success, 1 = invalid input, 2 = refused to terminate self, 3 = not found or access denied, 4 = system error
def terminate_process(pid: int, force: bool) -> int:
    try:
        if not isinstance(pid, int):
            return 1
        if pid <= 0 or pid > 4_000_000_000:
            return 1
        if pid == os.getpid():
            return 2

        # Choose signal depending on platform capability
        import signal
        sig = None
        if force and hasattr(signal, "SIGKILL"):
            sig = signal.SIGKILL
        else:
            # On Windows, SIGTERM is implemented by Python to terminate the process
            sig = getattr(signal, "SIGTERM")

        os.kill(pid, sig)
        return 0
    except ProcessLookupError:
        return 3
    except PermissionError:
        return 3
    except Exception:
        return 4


def _parse_pid(s: str) -> Optional[int]:
    try:
        s = s.strip()
        if not s:
            return None
        v = int(s, 10)
        return v
    except Exception:
        return None


def _is_force_flag(s: str) -> bool:
    if s is None:
        return False
    v = s.strip().lower()
    return v in ("-f", "--force")


def _print_result(pid: int, force: bool, code: int) -> None:
    print(f"Attempt terminate pid={pid} force={force} -> result={code}")


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        pid = _parse_pid(sys.argv[1])
        force = len(sys.argv) >= 3 and _is_force_flag(sys.argv[2])
        if pid is None:
            print("Invalid PID input. Usage: python task.py <pid> [--force|-f]")
            sys.exit(1)
        code = terminate_process(pid, force)
        _print_result(pid, force, code)
        sys.exit(0 if code == 0 else 1)
    else:
        # 5 Test cases
        self_pid = os.getpid()
        tests = [
            (-5, False),
            (0, True),
            (self_pid, False),
            (999_999_999, True),
            (1, False),
        ]
        for pid, force in tests:
            code = terminate_process(pid, force)
            _print_result(pid, force, code)