import hmac
import os
import time
from typing import Optional

class Session:
    __slots__ = ("token", "user_id", "client_ip", "user_agent", "expires_at")
    def __init__(self, token: str, user_id: str, client_ip: str, user_agent: str, expires_at: float):
        self.token = token
        self.user_id = user_id
        self.client_ip = client_ip
        self.user_agent = user_agent
        self.expires_at = expires_at

class SessionManager:
    def __init__(self, default_ttl_sec: int = 1800):
        self._sessions = {}  # token -> Session
        self._user_index = {}  # user_id -> set(tokens)
        self._default_ttl = max(1, min(default_ttl_sec, 24*3600))

    @staticmethod
    def _is_bad(s: Optional[str], max_len: int) -> bool:
        return s is None or len(s) == 0 or len(s) > max_len

    @staticmethod
    def _ct_eq(a: str, b: str) -> bool:
        try:
            return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
        except Exception:
            return False

    @staticmethod
    def _hex_token(nbytes: int = 32) -> str:
        return os.urandom(nbytes).hex()

    def _cleanup(self) -> None:
        now = time.time()
        expired = [t for t, s in self._sessions.items() if s.expires_at <= now]
        for t in expired:
            user_id = self._sessions[t].user_id
            del self._sessions[t]
            idx = self._user_index.get(user_id)
            if idx:
                idx.discard(t)
                if not idx:
                    self._user_index.pop(user_id, None)

    def create_session(self, user_id: str, client_ip: str, user_agent: str, ttl_sec: Optional[int] = None) -> Optional[str]:
        self._cleanup()
        if self._is_bad(user_id, 128) or self._is_bad(client_ip, 64) or self._is_bad(user_agent, 256):
            return None
        ttl = self._default_ttl if ttl_sec is None else max(1, min(ttl_sec, 24*3600))
        tok = self._hex_token()
        s = Session(tok, user_id, client_ip, user_agent, time.time() + ttl)
        self._sessions[tok] = s
        self._user_index.setdefault(user_id, set()).add(tok)
        return tok

    def validate_session(self, token: str, client_ip: str, user_agent: str) -> bool:
        self._cleanup()
        if self._is_bad(token, 128) or self._is_bad(client_ip, 64) or self._is_bad(user_agent, 256):
            return False
        s = self._sessions.get(token)
        if not s:
            return False
        if s.expires_at <= time.time():
            self.terminate_session(token)
            return False
        return self._ct_eq(s.client_ip, client_ip) and self._ct_eq(s.user_agent, user_agent)

    def get_user_if_valid(self, token: str, client_ip: str, user_agent: str) -> Optional[str]:
        return self._sessions[token].user_id if self.validate_session(token, client_ip, user_agent) else None

    def refresh_session(self, token: str, client_ip: str, user_agent: str) -> Optional[str]:
        self._cleanup()
        if not self.validate_session(token, client_ip, user_agent):
            return None
        old = self._sessions.get(token)
        if not old:
            return None
        new_tok = self._hex_token()
        new_s = Session(new_tok, old.user_id, old.client_ip, old.user_agent, time.time() + self._default_ttl)
        self._sessions[new_tok] = new_s
        self._user_index.setdefault(old.user_id, set()).add(new_tok)
        self.terminate_session(token)
        return new_tok

    def terminate_session(self, token: str) -> bool:
        s = self._sessions.pop(token, None)
        if s:
            idx = self._user_index.get(s.user_id)
            if idx:
                idx.discard(token)
                if not idx:
                    self._user_index.pop(s.user_id, None)
            return True
        return False

    def terminate_all_for_user(self, user_id: str) -> int:
        idx = self._user_index.pop(user_id, None)
        if not idx:
            return 0
        count = 0
        for t in list(idx):
            if t in self._sessions:
                del self._sessions[t]
                count += 1
        return count

if __name__ == "__main__":
    sm = SessionManager(1800)
    ip = "203.0.113.10"
    ua = "ExampleBrowser/1.0"
    bad_ip = "198.51.100.5"

    tok1 = sm.create_session("alice", ip, ua)
    print("T1 valid:", sm.validate_session(tok1, ip, ua))

    print("T2 wrong IP valid:", sm.validate_session(tok1, bad_ip, ua))

    tok2 = sm.refresh_session(tok1, ip, ua)
    print("T3 old valid:", sm.validate_session(tok1, ip, ua))
    print("T3 new valid:", sm.validate_session(tok2, ip, ua))

    tok3 = sm.create_session("bob", ip, ua, ttl_sec=1)
    time.sleep(1.2)
    print("T4 expired valid:", sm.validate_session(tok3, ip, ua))

    tok4 = sm.create_session("carol", ip, ua)
    print("T5 before terminate:", sm.validate_session(tok4, ip, ua))
    sm.terminate_session(tok4)
    print("T5 after terminate:", sm.validate_session(tok4, ip, ua))