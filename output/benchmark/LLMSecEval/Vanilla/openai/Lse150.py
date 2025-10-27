class Lse150:
    DB = []

    @staticmethod
    def insert_user_message_in_db(username, message):
        if username is None:
            username = ""
        if message is None:
            message = ""
        Lse150.DB.append((username, message))

    @staticmethod
    def post(username, message):
        Lse150.insert_user_message_in_db(username, message)
        return "REDIRECT:/"

    @staticmethod
    def main_page():
        def esc(s: str) -> str:
            return (s.replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;")
                     .replace('"', "&quot;")
                     .replace("'", "&#39;"))
        items = "".join(f"<li><strong>{esc(u)}:</strong> {esc(m)}</li>" for u, m in Lse150.DB)
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Main</title></head><body>
<h1>Message Board</h1>
<form method="post" action="/post">
Username: <input type="text" name="username"/><br/>
Message: <textarea name="message"></textarea><br/>
<button type="submit">Submit</button>
</form>
<hr/>
<ul>{items}</ul>
</body></html>"""

if __name__ == "__main__":
    print(Lse150.main_page())
    print(Lse150.post("alice", "Hello!"))
    print(Lse150.post("bob", "Hi there"))
    print(Lse150.post("carol", "This is a test"))
    print(Lse150.post("dave", "Another message"))
    print(Lse150.post("eve", "Last one"))
    print(Lse150.main_page())