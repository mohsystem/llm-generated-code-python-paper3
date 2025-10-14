import ctypes
import ctypes.util
from typing import Iterable, List

def _load_libc():
    # Try common libc names across platforms
    candidates = []
    name = ctypes.util.find_library('c')
    if name:
        candidates.append(name)
    # Windows
    win = ctypes.util.find_library('msvcrt')
    if win:
        candidates.append(win)
    # Fallback to current process (may expose malloc/free)
    candidates.append(None)

    last_err = None
    for cand in candidates:
        try:
            return ctypes.CDLL(cand) if cand is not None else ctypes.CDLL(None)
        except Exception as e:
            last_err = e
            continue
    raise OSError(f"Unable to load C standard library: {last_err}")

_libc = _load_libc()
_libc.malloc.restype = ctypes.c_void_p
_libc.malloc.argtypes = [ctypes.c_size_t]
_libc.free.restype = None
_libc.free.argtypes = [ctypes.c_void_p]

def allocate_and_process(data: Iterable[int]) -> int:
    if data is None:
        raise ValueError("Input cannot be None")

    # Ensure we have a concrete list of ints
    arr_list: List[int] = [int(x) for x in data]
    n = len(arr_list)

    # Secure overflow check for allocation size
    size_t_max = ctypes.c_size_t(-1).value
    elem_size = ctypes.sizeof(ctypes.c_int)
    if n < 0 or n > (size_t_max // elem_size):
        raise ValueError("Requested allocation size is too large.")

    total_bytes = n * elem_size

    ptr = None
    try:
        ptr = _libc.malloc(total_bytes)
        if not ptr and total_bytes != 0:
            raise MemoryError("malloc returned NULL")

        # Cast to pointer to int
        int_ptr = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_int))

        # Populate allocated memory
        for i, v in enumerate(arr_list):
            int_ptr[i] = int(v)

        # Process: compute sum reading from allocated memory
        s = 0
        for i in range(n):
            s += int_ptr[i]

        return s
    finally:
        if ptr:
            _libc.free(ptr)

if __name__ == "__main__":
    # 5 test cases
    tests = [
        [],                                  # sum = 0
        [1, 2, 3, 4, 5],                     # sum = 15
        [2_147_483_647, 1, -2],              # sum = 2147483646
        list(range(-500, 500)),              # sum = -500
        [1_000_000_000, 1_000_000_000, 1_000_000_000],  # sum = 3000000000
    ]

    for i, t in enumerate(tests, 1):
        print(f"Test {i} sum = {allocate_and_process(t)}")