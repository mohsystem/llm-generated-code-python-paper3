import ctypes
import ctypes.util
import sys

def _get_libc():
    if sys.platform.startswith("win"):
        return ctypes.CDLL("msvcrt.dll")
    name = ctypes.util.find_library("c")
    if not name:
        name = "libc.so.6"
    return ctypes.CDLL(name)

_libc = _get_libc()
_libc.malloc.restype = ctypes.c_void_p
_libc.malloc.argtypes = [ctypes.c_size_t]
_libc.free.argtypes = [ctypes.c_void_p]

def allocate_and_sum(n: int) -> int:
    if n <= 0:
        return 0
    elem_t = ctypes.c_longlong
    size = n * ctypes.sizeof(elem_t)
    ptr = _libc.malloc(size)
    if not ptr:
        raise MemoryError("malloc failed")
    try:
        arr = (elem_t * n).from_address(ptr)
        for i in range(n):
            arr[i] = i + 1
        total = 0
        for i in range(n):
            total += int(arr[i])
        return total
    finally:
        _libc.free(ptr)

if __name__ == "__main__":
    tests = [0, 1, 5, 10, 100000]
    for n in tests:
        print(f"n={n} sum={allocate_and_sum(n)}")