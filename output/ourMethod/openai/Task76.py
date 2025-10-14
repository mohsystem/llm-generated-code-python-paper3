import sys
import ssl
import urllib.request
import urllib.error
from typing import Optional

MAX_READ_BYTES = 1_048_576  # 1 MB cap
TIMEOUT = 10
USER_AGENT = "SecureTitleFetcher/1.0 (+https://example.com)"


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Only allow HTTPS redirects
        if not newurl.lower().startswith("https://"):
            raise urllib.error.HTTPError(newurl, code, "Redirected to non-HTTPS URL", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _extract_charset(content_type: Optional[str]) -> str:
    if content_type:
        parts = content_type.split(";")
        for part in parts[1:]:
            if "charset=" in part.lower():
                cs = part.split("=", 1)[1].strip().strip('"').strip("'")
                if cs:
                    return cs
    return "utf-8"


def _extract_title_from_html(html: str) -> str:
    l = html.lower()
    start = l.find("<title")
    if start == -1:
        return ""
    gt = l.find(">", start)
    if gt == -1:
        return ""
    end = l.find("</title>", gt + 1)
    if end == -1:
        return ""
    raw = html[gt + 1:end]
    # Remove inner tags
    out = []
    in_tag = False
    for ch in raw:
        if ch == "<":
            in_tag = True
            continue
        if ch == ">":
            in_tag = False
            continue
        if not in_tag:
            out.append(ch)
    title = "".join(out).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    while "  " in title:
        title = title.replace("  ", " ")
    return title


def fetch_title(url: str) -> str:
    try:
        if url is None:
            return "ERROR: URL is null"
        url = url.strip()
        if not url:
            return "ERROR: URL is empty"
        if len(url) > 2048:
            return "ERROR: URL too long"
        if not url.lower().startswith("https://"):
            return "ERROR: Only HTTPS URLs are allowed"

        ctx = ssl.create_default_context()
        opener = urllib.request.build_opener(HttpsOnlyRedirect())
        req = urllib.request.Request(
            url=url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.7",
            },
            method="GET",
        )

        with opener.open(req, timeout=TIMEOUT, context=ctx) as resp:
            ctype = resp.headers.get("Content-Type", "")
            charset = _extract_charset(ctype)
            data = bytearray()
            chunk_size = 4096
            closing_tag = b"</title>"
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                # Cap total bytes
                remaining = MAX_READ_BYTES - len(data)
                if remaining <= 0:
                    break
                if len(chunk) > remaining:
                    data.extend(chunk[:remaining])
                    break
                data.extend(chunk)
                # quick check to stop early if closing tag present in bytes (case-insensitive)
                if closing_tag in chunk.lower() or closing_tag in data.lower():
                    break

            try:
                html = data.decode(charset, errors="replace")
            except Exception:
                html = data.decode("utf-8", errors="replace")

            title = _extract_title_from_html(html)
            return title if title else "ERROR: Title not found"
    except urllib.error.HTTPError as e:
        msg = f"HTTPError {e.code}"
        return f"ERROR: {msg}"
    except urllib.error.URLError as e:
        return f"ERROR: {str(e.reason)[:200]}"
    except Exception as e:
        m = str(e).replace("\r", " ").replace("\n", " ")
        if len(m) > 200:
            m = m[:200] + "..."
        return f"ERROR: {m}"


def _run_tests() -> None:
    tests = sys.argv[1:] if len(sys.argv) > 1 else [
        "https://example.com",
        "https://www.wikipedia.org",
        "https://www.iana.org/domains/reserved",
        "https://www.gnu.org",
        "https://httpbin.org/html",
    ]
    for u in tests:
        print(f"{u} => {fetch_title(u)}")


if __name__ == "__main__":
    _run_tests()