from typing import Final


def sanitize_and_escape(text: str, max_len: int = 200) -> str:
    if text is None:
        return ""
    out_chars: list[str] = []
    count: int = 0
    for ch in text:
        if count >= max_len:
            break
        code = ord(ch)
        allowed = (code >= 0x20) or ch in ("\t", "\n", "\r")
        if not allowed:
            continue
        if ch == "&":
            out_chars.append("&amp;")
        elif ch == "<":
            out_chars.append("&lt;")
        elif ch == ">":
            out_chars.append("&gt;")
        elif ch == "\"":
            out_chars.append("&quot;")
        elif ch == "'":
            out_chars.append("&#x27;")
        else:
            out_chars.append(ch)
        count += 1
    return "".join(out_chars)


def render_page(user_input: str) -> str:
    safe: Final[str] = sanitize_and_escape(user_input, 200)
    html: str = (
        "<!DOCTYPE html>"
        "<html lang=\"en\">"
        "<head>"
        "<meta charset=\"UTF-8\"/>"
        "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"/>"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"/>"
        "<title>Safe Echo</title>"
        "<style>"
        "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;line-height:1.5;padding:20px;background:#f8f9fa;color:#212529;}"
        "pre{background:#fff;border:1px solid #dee2e6;border-radius:8px;padding:12px;white-space:pre-wrap;word-wrap:break-word;}"
        ".note{color:#6c757d;font-size:0.9em;margin-top:8px;}"
        "</style>"
        "</head>"
        "<body>"
        "<h1>Safe Echo</h1>"
        "<p>The content below is sanitized and length-limited to 200 characters.</p>"
        "<pre>"
        f"{safe}"
        "</pre>"
        "<p class=\"note\">Try different inputs by modifying the program arguments.</p>"
        "</body>"
        "</html>"
    )
    return html


def main() -> None:
    import sys
    # Optional: If there is a command-line argument, render that page first
    if len(sys.argv) > 1:
        print(render_page(sys.argv[1]))

    # 5 test cases
    tests = [
        "Hello, world!",
        "<script>alert('xss')</script>",
        "A" * 300,
        "Line1\nLine2 & Line3 <test>",
        "Emoji: 😊 and quotes \" ' & other <tags>",
    ]
    for t in tests:
        print(render_page(t))


if __name__ == "__main__":
    main()