import os
import sys
import time
import errno
import platform

def _is_alive_posix(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError as e:
        if e.errno == errno.ESRCH:
            return False
        return True

def _terminate_posix(pid: int, timeout_sec: float = 5.0) -> bool:
    # Try SIGTERM then escalate to SIGKILL if needed
    try:
        os.kill(pid, 15)  # SIGTERM
    except OSError as e:
        if e.errno == errno.ESRCH:
            return True
        return False

    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if not _is_alive_posix(pid):
            return True
        time.sleep(0.1)

    # Escalate
    try:
        os.kill(pid, 9)  # SIGKILL
    except OSError as e:
        if e.errno == errno.ESRCH:
            return True
        return False

    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if not _is_alive_posix(pid):
            return True
        time.sleep(0.1)

    return not _is_alive_posix(pid)

def _terminate_windows(pid: int, timeout_ms: int = 5000) -> bool:
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return False

    PROCESS_TERMINATE = 0x0001
    SYNCHRONIZE = 0x00100000
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    TerminateProcess = kernel32.TerminateProcess
    TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    TerminateProcess.restype = wintypes.BOOL

    WaitForSingleObject = kernel32.WaitForSingleObject
    WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    WaitForSingleObject.restype = wintypes.DWORD

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL

    access = PROCESS_TERMINATE | SYNCHRONIZE
    handle = OpenProcess(access, False, wintypes.DWORD(pid))
    if not handle:
        return False

    try:
        if not TerminateProcess(handle, 1):
            return False
        result = WaitForSingleObject(handle, wintypes.DWORD(timeout_ms))
        return result == WAIT_OBJECT_0
    finally:
        CloseHandle(handle)

def terminate_process(pid: int) -> bool:
    if not isinstance(pid, int):
        return False
    if pid <= 1:
        return False
    try:
        self_pid = os.getpid()
        if pid == self_pid:
            return False
    except Exception:
        pass

    system = platform.system().lower()
    if 'windows' in system:
        return _terminate_windows(pid)
    else:
        return _terminate_posix(pid)

def _parse_pid(s: str):
    try:
        return int(s.strip())
    except Exception:
        return None

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for a in sys.argv[1:]:
            pid = _parse_pid(a)
            if pid is None:
                print(f'PID "{a}" is invalid input.')
                continue
            ok = terminate_process(pid)
            print(f"Terminate PID {pid}: {'success' if ok else 'failed'}")
    else:
        # 5 test cases
        self_pid = os.getpid()
        tests = [-5, 0, 1, self_pid, 99999999]
        for pid in tests:
            ok = terminate_process(pid)
            print(f"Test terminate PID {pid}: {'success' if ok else 'failed'}")