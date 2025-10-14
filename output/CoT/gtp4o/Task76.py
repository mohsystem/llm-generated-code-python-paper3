import sys
import re
import urllib.request
import urllib.parse
import urllib.error
import ssl
import gzip

"""
Chain-of-Through process:
1) Problem understanding:
   - Retrieve HTML content from a provided HTTPS URL and return the page <title>.
2) Security requirements:
   - Enforce HTTPS only and block redirects to HTTP.
   - Set timeouts and limit read size to mitigate resource exhaustion.
3) Secure coding generation:
   - Validate URLs, implement custom redirect handler, decode safely, and use robust regex.
4) Code review:
   - Checked error handling, sanitization, and size-limited reads.
5) Secure code output:
   - Final function ensures HTTPS, limited redirects, timeouts, and safe parsing.
"""

MAX_BYTES = 1_048_576  # 1 MB cap
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme.lower() != "https":
            raise urllib.error.HTTPError(newurl, code, "Insecure redirect blocked (non-HTTPS)", headers, fp)
        return urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)

def _get_charset_from_ct(content_type: str) -> str:
    if not content_type:
        return "utf-8"
    parts = [p.strip() for p in content_type.split(";")]
    for p in parts:
        if p.lower().startswith("charset="):
            cs = p.split("=", 1)[1].strip()
            if cs:
                return cs
    return "utf-8"

def get_page_title(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            return ""
    except Exception:
        return ""

    headers = {
        "User-Agent": "Task76-Client/1.0 (+https)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip",
    }

    # SSL context: default secure settings
    context = ssl.create_default_context()

    opener = urllib.request.build_opener(
        SafeRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
        # Avoid adding HTTPHandler so non-HTTPS schemes won't be handled
    )

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with opener.open(req, timeout=10) as resp:
            raw = resp.read(MAX_BYTES + 1)
            # If server sent compressed data and library didn't decompress automatically
            enc = resp.headers.get("Content-Encoding", "")
            if enc and "gzip" in enc.lower():
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    # If decompression fails, fall back to original
                    pass
            content_type = resp.headers.get("Content-Type", "")
            charset = _get_charset_from_ct(content_type)
            html = raw[:MAX_BYTES].decode(charset, errors="replace")
    except Exception:
        return ""

    m = TITLE_RE.search(html)
    if not m:
        return ""
    title = m.group(1) or ""
    return re.sub(r"\s+", " ", title).strip()

if __name__ == "__main__":
    urls = sys.argv[1:] if len(sys.argv) > 1 else [
        "https://example.com",
        "https://www.wikipedia.org/",
        "https://www.mozilla.org/en-US/",
        "https://www.bbc.com/",
        "https://www.oracle.com/",
    ]
    for u in urls:
        print(f"{u} -> {get_page_title(u)}")