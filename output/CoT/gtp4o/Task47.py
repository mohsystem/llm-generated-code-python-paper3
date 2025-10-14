# Chain-of-Through secure implementation
# 1) Problem: fetch HTML from URL, extract <a href="...">text</a>, store into SQLite DB. Inputs: url, db_path. Output: count inserted.
# 2) Security: allow only http/https, timeouts, max size 2MB, parameterized SQL, safe user-agent, robust error handling.
# 3) Implementation: urllib with timeouts and size cap, regex for anchors, sqlite3 with prepared statements.
# 4) Review: validated scheme, capped size, parameterized SQL, no evals, graceful errors.
# 5) Output: final code below.

import re
import sqlite3
import urllib.request
import urllib.parse
import time

MAX_BYTES = 2_000_000

def _is_http_url(url: str) -> bool:
    try:
        p = urllib.parse.urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_url TEXT NOT NULL,
            link_url TEXT NOT NULL,
            link_text TEXT,
            scraped_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_links_page ON links(page_url)")

def _fetch_limited(url: str, max_bytes: int) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Task47Bot/1.0 (+https://example.local/bot)"}
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        cl = resp.headers.get("Content-Length")
        if cl is not None:
            try:
                if int(cl) > max_bytes:
                    raise RuntimeError("Content too large")
            except ValueError:
                pass
        # Read at most max_bytes
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            data = data[:max_bytes]
        return data

def _extract_links(html: str):
    if not html:
        return []
    # Remove scripts/styles for a bit less noise
    html = re.sub(r"(?is)<script.*?>.*?</script>", "", html)
    html = re.sub(r"(?is)<style.*?>.*?</style>", "", html)
    pattern = re.compile(r'(?is)<a\s+[^>]*href\s*=\s*"([^"]+)"[^>]*>(.*?)</a>')
    out = []
    for m in pattern.finditer(html):
        href = m.group(1).strip()
        text = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        out.append((href, text))
    return out

def scrape_and_store(url: str, db_path: str) -> int:
    if url is None or db_path is None:
        raise ValueError("Null arguments")
    if not _is_http_url(url):
        raise ValueError("Only http/https URLs allowed")
    raw = _fetch_limited(url, MAX_BYTES)
    html = raw.decode("utf-8", "ignore")
    links = _extract_links(html)
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    inserted = 0
    with sqlite3.connect(db_path) as conn:
        _ensure_schema(conn)
        cur = conn.cursor()
        cur.executemany(
            "INSERT INTO links(page_url, link_url, link_text, scraped_at) VALUES(?,?,?,?)",
            [(url, href, text, when) for (href, text) in links]
        )
        inserted = cur.rowcount if cur.rowcount is not None else len(links)
        conn.commit()
    return inserted

if __name__ == "__main__":
    db = "scrape_demo_py.db"
    tests = [
        "https://example.com",
        "https://www.iana.org/domains/reserved",
        "https://httpbin.org/html",
        "https://www.wikipedia.org",
        "https://www.rfc-editor.org/rfc/rfc2616",
    ]
    for t in tests:
        try:
            n = scrape_and_store(t, db)
            print(f"Scraped {t} -> stored {n} links.")
        except Exception as e:
            print(f"Error scraping {t}: {e}")