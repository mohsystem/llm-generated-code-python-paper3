from typing import Dict, List, Any


def _is_valid_name(name: str) -> bool:
    if not isinstance(name, str):
        return False
    n = len(name)
    if n < 1 or n > 64:
        return False
    for ch in name:
        if not (ch.isalnum() or ch in "_-./"):
            return False
    return True


class JndiLikeContext:
    def __init__(self, initial: Dict[str, Any]) -> None:
        self._bindings: Dict[str, Any] = {}
        for k, v in initial.items():
            if _is_valid_name(k):
                if isinstance(v, (str, int, float, bool, SafeResource)):
                    self._bindings[k] = v

    def lookup(self, name: str) -> Any:
        if not _is_valid_name(name):
            raise KeyError("invalid-name")
        if name not in self._bindings:
            raise KeyError("not-found")
        return self._bindings[name]

    def rebind(self, name: str, value: Any) -> None:
        if not _is_valid_name(name):
            raise KeyError("invalid-name")
        if not isinstance(value, (str, int, float, bool, SafeResource)):
            raise ValueError("unsupported-type")
        self._bindings[name] = value


class SafeResource:
    def __init__(self, name: str, capacity: int) -> None:
        self.name = name or "resource"
        self.capacity = max(0, min(int(capacity), 1_000_000))

    def __str__(self) -> str:
        return f"SafeResource(name={self.name},capacity={self.capacity})"


def jndi_lookup(initial_bindings: Dict[str, Any], names: List[str]) -> List[str]:
    ctx = JndiLikeContext(initial_bindings)
    results: List[str] = []
    for n in names:
        if not _is_valid_name(n):
            results.append("ERROR: invalid-name")
            continue
        try:
            val = ctx.lookup(n)
            if isinstance(val, (int, float, bool)):
                results.append(str(val))
            elif isinstance(val, str):
                results.append(val[:256])
            else:
                results.append(str(val))
        except KeyError as e:
            msg = str(e)
            if "not-found" in msg:
                results.append("NOT_FOUND")
            else:
                results.append("ERROR: invalid-name")
        except Exception:
            results.append("ERROR: lookup-failed")
    return results


def _print_case(title: str, res: List[str]) -> None:
    print(f"{title}: {res}")


if __name__ == "__main__":
    initial = {
        "config/db/url": "jdbc:postgresql://localhost:5432/app",
        "config/maxConnections": 20,
        "service/cache": SafeResource("CacheService", 128),
        "feature/enabled": True,
        "metrics.endpoint": "http://localhost:8080/metrics",
    }

    # Test 1: Found entries
    r1 = jndi_lookup(initial, ["config/db/url", "config/maxConnections", "service/cache"])
    _print_case("Test1", r1)

    # Test 2: Mixed found/not found
    r2 = jndi_lookup(initial, ["config/missing", "feature/enabled", "service/unknown"])
    _print_case("Test2", r2)

    # Test 3: Invalid names
    r3 = jndi_lookup(initial, ["bad name", "toolong_" * 9 + "X", "valid.name-OK/1"])
    _print_case("Test3", r3)

    # Test 4: Override binding behavior simulated by new initial
    initial2 = dict(initial)
    initial2["config/maxConnections"] = 50
    r4 = jndi_lookup(initial2, ["config/maxConnections", "metrics.endpoint"])
    _print_case("Test4", r4)

    # Test 5: Edge characters allowed
    r5 = jndi_lookup(initial, ["metrics.endpoint", "valid.name-OK/1"])
    _print_case("Test5", r5)