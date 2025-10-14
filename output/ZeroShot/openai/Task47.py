import sqlite3
import urllib.request
import urllib.parse
import urllib.error
import urllib.robotparser
from html.parser import HTMLParser
from datetime import datetime
from typing import Dict, Any, List, Tuple


class _SafeHTMLParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.in_title = False
        self.title_chunks: List[str] = []
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]):
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "a":
            href = None
            for k, v in attrs:
                if k.lower() == "href":
                    href = v
                    break
            if href:
                # Normalize and keep only http/https
                abs_url = urllib.parse.urljoin(self.base_url, href)
                parsed = urllib.parse.urlparse(abs_url)
                if parsed.scheme in ("http", "https") and parsed.netloc:
                    # strip fragment
                    abs_url = urllib.parse.urlunparse(parsed._replace(fragment=""))
                    self.links.append(abs_url)

    def handle_endtag(self, tag: str):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str):
        if self.in_title:
            self.title_chunks.append(data)

    def get_title(self) -> str:
        title = "".join(self.title_chunks).strip()
        # limit size to avoid excessive storage
        return title[:512]


def _validate_url(url: str) -> str:
    if not isinstance(url, str):
        raise ValueError("URL must be a string")
    if len(url) > 2048:
        raise ValueError("URL too long")
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are allowed")
    if not parsed.netloc:
        raise ValueError("URL must include a host")
    # Normalize URL: remove fragment, default path
    if not parsed.path:
        parsed = parsed._replace(path="/")
    parsed = parsed._replace(fragment="")
    return urllib.parse.urlunparse(parsed)


def _is_allowed_by_robots(url: str, user_agent: str, timeout: float = 10.0) -> bool:
    parsed = urllib.parse.urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = urllib.robotparser.RobotFileParser()
    try:
        req = urllib.request.Request(
            robots_url,
            headers={"User-Agent": user_agent},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Limit robots.txt size to 100KB
            content = resp.read(102400)
            rp.parse(content.decode("utf-8", errors="ignore").splitlines())
    except Exception:
        # If robots.txt cannot be fetched, default to disallow scraping to be safe
        return False
    return rp.can_fetch(user_agent, url)


def _fetch_html(url: str, user_agent: str, timeout: float = 10.0, max_bytes: int = 1_000_000) -> Tuple[str, str]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.7",
            "Connection": "close",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        ctype = resp.headers.get("Content-Type", "")
        if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
            raise ValueError("URL did not return HTML content")
        # Stream-read up to max_bytes
        remaining = max_bytes
        chunks: List[bytes] = []
        while remaining > 0:
            chunk = resp.read(min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        html_bytes = b"".join(chunks)
        # Choose charset from header if available
        charset = "utf-8"
        if "charset=" in ctype:
            try:
                charset = ctype.split("charset=", 1)[1].split(";")[0].strip()
            except Exception:
                pass
        html_text = html_bytes.decode(charset, errors="replace")
        return ctype, html_text


def _init_db(db_path: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                title TEXT,
                retrieved_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_id INTEGER NOT NULL,
                link_url TEXT NOT NULL,
                FOREIGN KEY(page_id) REFERENCES pages(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_links_page_id ON links(page_id);")


def scrape_and_store(url: str, db_path: str) -> Dict[str, Any]:
    user_agent = "Task47Bot/1.0 (+https://example.invalid/bot)"
    norm_url = _validate_url(url)
    _init_db(db_path)

    if not _is_allowed_by_robots(norm_url, user_agent):
        return {
            "url": norm_url,
            "status": "blocked_by_robots",
            "inserted": False,
            "page_id": None,
            "links_inserted": 0,
        }

    try:
        _, html = _fetch_html(norm_url, user_agent=user_agent)
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as e:
        return {
            "url": norm_url,
            "status": f"fetch_error: {type(e).__name__}",
            "inserted": False,
            "page_id": None,
            "links_inserted": 0,
        }

    parser = _SafeHTMLParser(base_url=norm_url)
    parser.feed(html)
    title = parser.get_title()
    # Limit stored links to a reasonable amount for safety
    links = parser.links[:200]

    retrieved_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    page_id = None
    links_inserted = 0
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys=ON;")
        cur = conn.cursor()
        # Upsert page
        cur.execute(
            """
            INSERT INTO pages(url, title, retrieved_at)
            VALUES (?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                title=excluded.title,
                retrieved_at=excluded.retrieved_at
            """,
            (norm_url, title, retrieved_at),
        )
        # Retrieve page id
        cur.execute("SELECT id FROM pages WHERE url = ?", (norm_url,))
        row = cur.fetchone()
        if row:
            page_id = int(row[0])
        # Remove old links to avoid duplicates on refresh
        if page_id is not None:
            cur.execute("DELETE FROM links WHERE page_id = ?", (page_id,))
        # Insert links
        if page_id is not None and links:
            cur.executemany(
                "INSERT INTO links(page_id, link_url) VALUES (?, ?)",
                [(page_id, l) for l in links],
            )
            links_inserted = cur.rowcount if cur.rowcount is not None else 0
        conn.commit()

    return {
        "url": norm_url,
        "status": "ok",
        "inserted": True,
        "page_id": page_id,
        "title": title,
        "links_count": len(links),
        "links_inserted": links_inserted,
        "retrieved_at": retrieved_at,
        "db_path": db_path,
    }


def run_tests() -> List[Dict[str, Any]]:
    db_path = "task47.db"
    tests = [
        "https://example.com/",
        "https://example.org/",
        "https://example.net/",
        "https://httpbin.org/html",
        "https://www.iana.org/domains/example",
    ]
    results = []
    for u in tests:
        try:
            res = scrape_and_store(u, db_path)
        except Exception as ex:
            res = {"url": u, "status": f"unhandled_error: {type(ex).__name__}"}
        results.append(res)
    return results


if __name__ == "__main__":
    # Execute 5 test cases
    for r in run_tests():
        print(r)