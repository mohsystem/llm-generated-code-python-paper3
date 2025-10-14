import os
import sys
import time
import platform
import signal
import subprocess
import ctypes

def terminate_process(pid: int) -> bool:
    if os.name == 'nt':
        PROCESS_TERMINATE = 0x0001
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
        if not handle:
            return False
        try:
            res = kernel32.TerminateProcess(handle, 1)
            kernel32.CloseHandle(handle)
            return res != 0
        except Exception:
            kernel32.CloseHandle(handle)
            return False
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        # wait up to 2 seconds
        for _ in range(20):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            except PermissionError:
                pass
            time.sleep(0.1)
        # escalate
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        for _ in range(20):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            time.sleep(0.1)
        return False

def spawn_dummy_process():
    if os.name == 'nt':
        # Use shell to handle redirection
        return subprocess.Popen("ping -n 30 127.0.0.1 > nul", shell=True)
    else:
        return subprocess.Popen(["sleep", "30"])

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for s in sys.argv[1:]:
            try:
                pid = int(s)
            except ValueError:
                print(f"Invalid PID: {s}")
                continue
            ok = terminate_process(pid)
            print(f"PID {pid} terminated: {ok}")
    else:
        # 5 test cases: spawn and terminate
        procs = [spawn_dummy_process() for _ in range(5)]
        for p in procs:
            print(f"Spawned dummy process PID: {p.pid}")
        for p in procs:
            ok = terminate_process(p.pid)
            print(f"Test terminate PID {p.pid}: {ok}")