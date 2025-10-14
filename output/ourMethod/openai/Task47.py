import json
import sqlite3
import ssl
import sys
import time
from html.parser import HTMLParser
from typing import List, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self.title_parts: List[str] = []
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]) -> None:
        if tag.lower() == "title":
            self._in_title = True
        if tag.lower() == "a":
            for (k, v) in attrs:
                if k.lower() == "href" and isinstance(v, str):
                    href = v.strip()
                    if href.startswith("http://") or href.startswith("https://"):
                        if len(href) <= 2048:
                            self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and isinstance(data, str):
            self.title_parts.append(data)


def _fetch_html(url: str, max_bytes: int = 1_048_576) -> str:
    if not isinstance(url, str) or not url:
        raise ValueError("URL must be a non-empty string.")
    if len(url) > 2048:
        raise ValueError("URL too long.")
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS URLs are allowed.")
    if not parsed.hostname:
        raise ValueError("URL must include a valid hostname.")

    ctx = ssl.create_default_context()  # Validates certificates and hostnames by default.

    req = Request(url, headers={"User-Agent": "Task47Scraper/1.0 (+https://example.local)"}, method="GET")
    with urlopen(req, context=ctx, timeout=20) as resp:
        ct = resp.headers.get("Content-Type", "")
        # proceed even if not text/html; still enforce size limits
        read = 0
        chunks: List[bytes] = []
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            read += len(chunk)
            if read > max_bytes:
                # truncate to max_bytes
                over = read - max_bytes
                if over < len(chunk):
                    chunks.append(chunk[: len(chunk) - over])
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.decode("latin-1", errors="replace")


def _parse_html(html: str) -> Tuple[str, List[str]]:
    limited = html[:1_200_000] if isinstance(html, str) else ""
    parser = _Parser()
    parser.feed(limited)
    title = " ".join(parser.title_parts).strip()
    if len(title) > 512:
        title = title[:512]
    return title, parser.links


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pages (
            url TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            links TEXT NOT NULL,
            ts TEXT NOT NULL
        )
        """
    )
    conn.commit()


def scrape_and_store(url: str, db_path: str) -> dict:
    html = _fetch_html(url)
    title, links = _parse_html(html)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    record = {"url": url, "title": title, "links": links, "timestamp": ts}

    if not isinstance(db_path, str) or not db_path:
        raise ValueError("db_path must be a non-empty string.")
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        _init_db(conn)
        conn.execute(
            "INSERT OR REPLACE INTO pages(url, title, links, ts) VALUES (?, ?, ?, ?)",
            (record["url"], record["title"], json.dumps(record["links"], ensure_ascii=False), record["timestamp"]),
        )
        conn.commit()
    return record


def main() -> None:
    db_file = "py_scrape.db"
    tests = [
        "https://example.com/",
        "https://www.iana.org/domains/reserved",
        "https://www.wikipedia.org/",
        "https://www.gnu.org/",
        "https://httpbin.org/html",
    ]
    for u in tests:
        try:
            r = scrape_and_store(u, db_file)
            print(f"Scraped: {r['url']} | title={r['title']} | links={len(r['links'])}")
        except Exception as e:
            print(f"Failed for {u} -> {e}", file=sys.stderr)


if __name__ == "__main__":
    main()