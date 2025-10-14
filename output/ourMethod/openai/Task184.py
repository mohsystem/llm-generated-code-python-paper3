from __future__ import annotations
import sys
from typing import Set, List
import secrets
import re

# Global registry ensuring uniqueness among existing robots
_REGISTRY: Set[str] = set()
_MAX_NAMES = 26 * 26 * 1000  # 676000

def _generate_candidate_name() -> str:
    letters = ''.join(chr(ord('A') + secrets.randbelow(26)) for _ in range(2))
    digits = ''.join(chr(ord('0') + secrets.randbelow(10)) for _ in range(3))
    return letters + digits

_NAME_RE = re.compile(r"^[A-Z]{2}\d{3}$")

def _validate_name_format(name: str) -> bool:
    return bool(_NAME_RE.match(name))

def _acquire_unique_name() -> str:
    if len(_REGISTRY) >= _MAX_NAMES:
        raise RuntimeError("Name space exhausted: cannot allocate more unique names")
    # Attempt until success (collision probability is low)
    attempts = 0
    while attempts < _MAX_NAMES * 2:
        candidate = _generate_candidate_name()
        if not _validate_name_format(candidate):
            attempts += 1
            continue
        if candidate not in _REGISTRY:
            _REGISTRY.add(candidate)
            return candidate
        attempts += 1
    raise RuntimeError("Unable to acquire a unique name after many attempts")

def _release_name(name: str | None) -> bool:
    if not name:
        return False
    if name in _REGISTRY:
        _REGISTRY.remove(name)
        return True
    return False

class Robot:
    def __init__(self) -> None:
        self._name: str | None = None

    def get_name(self) -> str:
        if self._name is None:
            self._name = _acquire_unique_name()
        return self._name

    def reset(self) -> bool:
        if self._name is None:
            return False
        _release_name(self._name)
        self._name = None
        return True

# Test helpers
def _is_unique(names: List[str]) -> bool:
    return len(set(names)) == len(names)

# Tests
def test1_single_robot_name_pattern() -> bool:
    r = Robot()
    n = r.get_name()
    return _validate_name_format(n)

def test2_multiple_robots_unique() -> bool:
    robots = [Robot() for _ in range(10)]
    names = [r.get_name() for r in robots]
    return _is_unique(names)

def test3_reset_changes_and_unique() -> bool:
    r1 = Robot()
    r2 = Robot()
    n1 = r1.get_name()
    n2 = r2.get_name()
    before_unique = n1 != n2
    r1.reset()
    n1b = r1.get_name()
    changed = n1 != n1b
    still_unique = n1b != r2.get_name()
    return before_unique and changed and still_unique

def test4_repeated_resets_yield_different_names() -> bool:
    r = Robot()
    seen: Set[str] = set()
    for _ in range(6):
        n = r.get_name()
        if n in seen:
            return False
        seen.add(n)
        r.reset()
    return True

def test5_stress_uniqueness() -> bool:
    robots = [Robot() for _ in range(500)]
    names = [r.get_name() for r in robots]
    return _is_unique(names)

if __name__ == "__main__":
    print("Test1 pattern:", test1_single_robot_name_pattern())
    print("Test2 uniqueness among 10:", test2_multiple_robots_unique())
    print("Test3 reset changes and unique:", test3_reset_changes_and_unique())
    print("Test4 repeated resets yield different names:", test4_repeated_resets_yield_different_names())
    print("Test5 stress uniqueness among 500:", test5_stress_uniqueness())