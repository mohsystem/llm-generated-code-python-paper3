class Lse149:
    MAX_USER_LEN = 50
    MAX_MSG_LEN = 500
    DB = []

    @staticmethod
    def _sanitize(s: str, max_len: int) -> str:
        if s is None:
            return ""
        out = []
        for ch in s:
            if len(out) >= max_len:
                break
            if 32 <= ord(ch) != 127:
                out.append(ch)
        return "".join(out).strip()

    @staticmethod
    def _html_escape(s: str) -> str:
        if s is None:
            return ""
        return (
            s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;")
        )

    @staticmethod
    def insert_user_message_in_db(username: str, message: str) -> bool:
        user = Lse149._sanitize(username, Lse149.MAX_USER_LEN)
        msg = Lse149._sanitize(message, Lse149.MAX_MSG_LEN)
        if not user or not msg:
            return False
        Lse149.DB.append((user, msg))
        return True

    @staticmethod
    def route_post(username: str, message: str) -> str:
        Lse149.insert_user_message_in_db(username, message)
        return "REDIRECT: /"

    @staticmethod
    def route_root() -> str:
        items = []
        for user, msg in Lse149.DB:
            items.append(f"<li><strong>{Lse149._html_escape(user)}</strong>: {Lse149._html_escape(msg)}</li>")
        html = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Messages</title></head><body>"
        html += "<h1>Messages</h1><ul>" + "".join(items) + "</ul></body></html>"
        return html


if __name__ == "__main__":
    # 5 test cases
    print(Lse149.route_post("alice", "Hello, world!"))
    print(Lse149.route_post("bob", "Testing <b>bold</b> & \"quotes\""))
    print(Lse149.route_post("charlie", "Line1\nLine2 should be sanitized for control chars."))
    print(Lse149.route_post("dave", "This is a very long message that will be trimmed if too long." * 20))
    print(Lse149.route_post(" eve ", "   spaced input   "))

    print(Lse149.route_root())