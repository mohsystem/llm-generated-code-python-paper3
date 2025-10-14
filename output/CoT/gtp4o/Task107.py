# Step 1: Problem understanding
# Provide a secure, JNDI-like in-memory context with bind and lookup for string resources.
# Inputs: dict of initial bindings and list of names to lookup.
# Output: dict of name->value or markers for not found/invalid.
# Step 2: Security - no network, no dynamic code; validate names and value sizes; restrict to strings.

import re
from typing import Dict, List

NAME_RE = re.compile(r'^(?!/)(?!.*//)[A-Za-z0-9_.\-/]{1,256}(?<!/)$')
MAX_VALUE_LENGTH = 8192

class SafeContext:
    def __init__(self) -> None:
        self._store: Dict[str, str] = {}

    @staticmethod
    def _valid_name(name: str) -> bool:
        return name is not None and bool(NAME_RE.match(name))

    @staticmethod
    def _validate_value(value: str) -> None:
        if value is None:
            raise ValueError("Null value not allowed")
        if len(value) > MAX_VALUE_LENGTH:
            raise ValueError("Value too large")

    def bind(self, name: str, value: str) -> None:
        if not self._valid_name(name):
            raise ValueError(f"Invalid name: {name}")
        self._validate_value(value)
        if name in self._store:
            raise KeyError(f"Already bound: {name}")
        self._store[name] = value

    def rebind(self, name: str, value: str) -> None:
        if not self._valid_name(name):
            raise ValueError(f"Invalid name: {name}")
        self._validate_value(value)
        self._store[name] = value

    def lookup(self, name: str) -> str:
        if not self._valid_name(name):
            raise ValueError(f"Invalid name: {name}")
        if name not in self._store:
            raise KeyError(f"Name not found: {name}")
        return self._store[name]

def perform_lookups(initial_bindings: Dict[str, str], lookup_names: List[str]) -> Dict[str, str]:
    ctx = SafeContext()
    if initial_bindings:
        for k, v in initial_bindings.items():
            if not SafeContext._valid_name(k):
                raise ValueError(f"Invalid name: {k}")
            SafeContext._validate_value(v)
            ctx.rebind(k, v)
    results: Dict[str, str] = {}
    for name in (lookup_names or []):
        if not SafeContext._valid_name(name):
            results[name] = "<INVALID_NAME>"
            continue
        try:
            results[name] = ctx.lookup(name)
        except KeyError:
            results[name] = "<NOT_FOUND>"
    return results

if __name__ == "__main__":
    # 5 test cases
    print("Test1:", perform_lookups({"config/db/url": "jdbc:h2:mem:test1", "feature/flagA": "true"},
                                   ["config/db/url", "feature/flagA", "missing/name"]))

    print("Test2:", perform_lookups({"service/endpoint": "https://api.v2.example.com"},
                                   ["service/endpoint"]))

    print("Test3:", perform_lookups({"app/env/prod/log/level": "INFO", "app/env/prod/threads": "16"},
                                   ["app/env/prod/log/level", "app/env/prod/threads"]))

    try:
        print("Test4:", perform_lookups({"/bad/leading/slash": "x"}, ["/bad/leading/slash", "also//bad"]))
    except ValueError as e:
        print("Test4: Caught expected exception:", e)

    big = "0123456789" * 1000
    print("Test5:", perform_lookups({"blob/data": big}, ["blob/data", "not/present"]))