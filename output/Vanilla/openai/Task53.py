import time
import uuid

class Session:
    def __init__(self, session_id: str, user_id: str, expiry_ms: int):
        self.session_id = session_id
        self.user_id = user_id
        self.expiry_ms = expiry_ms
        self.attrs = {}

class SessionManager:
    def __init__(self):
        self.sessions = {}

    def _now(self) -> int:
        return int(time.time() * 1000)

    def create_session(self, user_id: str, ttl_ms: int) -> str:
        sid = str(uuid.uuid4())
        self.sessions[sid] = Session(sid, user_id, self._now() + ttl_ms)
        return sid

    def _is_expired(self, s: Session) -> bool:
        return s.expiry_ms < self._now()

    def validate_session(self, session_id: str) -> bool:
        s = self.sessions.get(session_id)
        if not s:
            return False
        if self._is_expired(s):
            self.sessions.pop(session_id, None)
            return False
        return True

    def get_user(self, session_id: str):
        return self.sessions[session_id].user_id if self.validate_session(session_id) else None

    def set_attribute(self, session_id: str, key: str, value: str) -> bool:
        if not self.validate_session(session_id):
            return False
        self.sessions[session_id].attrs[key] = value
        return True

    def get_attribute(self, session_id: str, key: str):
        if not self.validate_session(session_id):
            return None
        return self.sessions[session_id].attrs.get(key)

    def touch(self, session_id: str, ttl_extend_ms: int) -> bool:
        if not self.validate_session(session_id):
            return False
        self.sessions[session_id].expiry_ms = self._now() + ttl_extend_ms
        return True

    def invalidate_session(self, session_id: str) -> bool:
        return self.sessions.pop(session_id, None) is not None

    def cleanup_expired(self) -> int:
        now = self._now()
        to_remove = [sid for sid, s in self.sessions.items() if s.expiry_ms < now]
        for sid in to_remove:
            self.sessions.pop(sid, None)
        return len(to_remove)

    def count_sessions(self) -> int:
        return len(self.sessions)

def main():
    sm = SessionManager()

    sid1 = sm.create_session("userA", 10000)
    print(f"T1_valid={sm.validate_session(sid1)}, user={sm.get_user(sid1)}, count={sm.count_sessions()}")

    sm.set_attribute(sid1, "role", "admin")
    print(f"T2_role={sm.get_attribute(sid1, 'role')}")

    touched = sm.touch(sid1, 10000)
    print(f"T3_touched={touched}, stillValid={sm.validate_session(sid1)}")

    sm.invalidate_session(sid1)
    print(f"T4_validAfterInvalidate={sm.validate_session(sid1)}, count={sm.count_sessions()}")

    sid2 = sm.create_session("userB", 0)
    sid3 = sm.create_session("userC", -1000)
    removed = sm.cleanup_expired()
    print(f"T5_removed={removed}, finalCount={sm.count_sessions()}")

if __name__ == "__main__":
    main()