import time
from typing import Dict, List

class Task123:
    class Session:
        def __init__(self, sid: str, user_id: str, created_at: int, ttl_ms: int):
            self.id = sid
            self.user_id = user_id
            self.created_at = created_at
            self.last_access = created_at
            self.ttl_ms = ttl_ms
            self.invalidated = False

        def __repr__(self):
            return f"Session(id={self.id}, user={self.user_id}, created={self.created_at}, last={self.last_access}, ttl={self.ttl_ms}, invalidated={self.invalidated})"

    class SessionManager:
        def __init__(self):
            self._sessions: Dict[str, Task123.Session] = {}
            self._counter = 0

        def _expired(self, s: 'Task123.Session', now_ms: int) -> bool:
            return (now_ms - s.last_access) > s.ttl_ms

        def create_session(self, user_id: str, now_ms: int, ttl_ms: int) -> str:
            self._counter += 1
            sid = f"S{self._counter}"
            self._sessions[sid] = Task123.Session(sid, user_id, now_ms, ttl_ms)
            return sid

        def is_active(self, session_id: str, now_ms: int) -> bool:
            s = self._sessions.get(session_id)
            if not s or s.invalidated or self._expired(s, now_ms):
                return False
            return True

        def touch(self, session_id: str, now_ms: int) -> bool:
            s = self._sessions.get(session_id)
            if not s or s.invalidated or self._expired(s, now_ms):
                return False
            s.last_access = now_ms
            return True

        def invalidate(self, session_id: str) -> bool:
            s = self._sessions.get(session_id)
            if not s or s.invalidated:
                return False
            s.invalidated = True
            return True

        def purge_expired(self, now_ms: int) -> int:
            to_remove = [sid for sid, s in self._sessions.items() if s.invalidated or self._expired(s, now_ms)]
            for sid in to_remove:
                del self._sessions[sid]
            return len(to_remove)

        def list_active_sessions(self, user_id: str, now_ms: int) -> List[str]:
            ids = [s.id for s in self._sessions.values() if s.user_id == user_id and not s.invalidated and not self._expired(s, now_ms)]
            return sorted(ids)

        def get_session_info(self, session_id: str) -> str:
            s = self._sessions.get(session_id)
            return repr(s) if s else None

if __name__ == "__main__":
    mgr = Task123.SessionManager()
    # Test 1
    s1 = mgr.create_session("alice", 1000, 30000)
    print(f"Test1:isActive(s1@1000)={mgr.is_active(s1, 1000)}")
    print(f"Test1:listActive(alice@1000)={mgr.list_active_sessions('alice', 1000)}")
    # Test 2
    print(f"Test2:touch(s1@20000)={mgr.touch(s1, 20000)}")
    print(f"Test2:isActive(s1@20000)={mgr.is_active(s1, 20000)}")
    # Test 3
    s2 = mgr.create_session("alice", 21000, 30000)
    print(f"Test3:listActive(alice@21000)={mgr.list_active_sessions('alice', 21000)}")
    # Test 4
    sb = mgr.create_session("bob", 1000, 10000)
    print(f"Test4:isActive(sb@12000)={mgr.is_active(sb, 12000)}")
    print(f"Test4:purged@12000={mgr.purge_expired(12000)}")
    print(f"Test4:listActive(bob@12000)={mgr.list_active_sessions('bob', 12000)}")
    # Test 5
    print(f"Test5:invalidate(s1)={mgr.invalidate(s1)}")
    print(f"Test5:listActive(alice@22000)={mgr.list_active_sessions('alice', 22000)}")