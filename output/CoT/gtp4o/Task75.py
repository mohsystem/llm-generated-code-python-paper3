import os
import signal
import sys
import time
from typing import Tuple

def _is_windows() -> bool:
    return os.name == 'nt'

def _is_alive(pid: int) -> bool:
    try:
        # On both POSIX and Windows (Py3.8+), sending signal 0 checks existence/permission
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we may lack permission
        return True
    except OSError:
        # Other OS errors: assume may exist
        return True

def terminate_process(pid: int, timeout_sec: float = 2.0) -> Tuple[bool, str]:
    # Validate PID
    if not isinstance(pid, int):
        return (False, "PID must be an integer")
    if pid <= 0:
        return (False, "PID must be greater than 0")

    self_pid = os.getpid()
    if pid == self_pid:
        return (False, "Refusing to terminate the current process")

    if _is_windows():
        if pid <= 4:
            return (False, "Refusing to terminate likely critical/system PID on Windows (<=4)")
    else:
        if pid <= 1:
            return (False, "Refusing to terminate init/system PID on POSIX (<=1)")

    # If not alive, consider already terminated
    if not _is_alive(pid):
        return (True, "Process not running")

    # Attempt graceful termination (POSIX), or TerminateProcess on Windows via os.kill
    try:
        sig = signal.SIGTERM
        os.kill(pid, sig)
    except ProcessLookupError:
        return (True, "Process not running")
    except PermissionError:
        return (False, "Permission denied to terminate the process")
    except Exception as e:
        return (False, f"Error sending initial terminate signal: {e}")

    # Wait for process to exit
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if not _is_alive(pid):
            return (True, "Process terminated gracefully")
        time.sleep(0.05)

    # Escalate on POSIX with SIGKILL if still alive
    if not _is_windows():
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return (True, "Process not running after graceful attempt")
        except PermissionError:
            return (False, "Permission denied to forcefully terminate the process")
        except Exception as e:
            return (False, f"Error sending SIGKILL: {e}")

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if not _is_alive(pid):
                return (True, "Process forcefully terminated")
            time.sleep(0.05)

    else:
        # On Windows, SIGTERM via os.kill already maps to TerminateProcess
        # Wait a bit more
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if not _is_alive(pid):
                return (True, "Process terminated")
            time.sleep(0.05)

    # Final check
    if not _is_alive(pid):
        return (True, "Process not alive after attempts")
    return (False, "Failed to terminate process within time limit")

def _parse_int(s: str):
    try:
        return int(s.strip())
    except Exception:
        return None

if __name__ == "__main__":
    pids = []
    if len(sys.argv) > 1:
        for a in sys.argv[1:]:
            v = _parse_int(a)
            if v is not None:
                pids.append(v)
    else:
        # 5 test cases (safe/demonstrative)
        self_pid = os.getpid()
        pids = [-1, 0, 1, self_pid, 999999]
        print("No arguments provided. Running 5 demonstrative test cases.")

    for pid in pids:
        ok, msg = terminate_process(pid)
        print(f"Terminate PID {pid}: {'SUCCESS/NOT ALIVE' if ok else 'FAILED/ALIVE'} - {msg}")