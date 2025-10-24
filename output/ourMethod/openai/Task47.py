import sys
import sqlite3
import ssl
import socket
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Tuple, Optional, Dict, Any
from urllib.parse import urlparse, urljoin
from urllib import robotparser

import requests
from bs4 import BeautifulSoup


USER_AGENT: str = "SecureScraper/1.0 (+https://example.invalid)"
DEFAULT_CONNECT_TIMEOUT: float = 7.0
DEFAULT_READ_TIMEOUT: float = 12.0
MAX_URL_LENGTH: int = 2048
MAX_LINKS_STORED: int = 50


@dataclass(frozen=True)
class PageData:
    url: str
    fetched_at_utc_iso: str
    title: Optional[str]
    description: Optional[str]
    links: List[Tuple[str, Optional[str]]]


def validate_url(input_url: str) -> str:
    """
    Validate and normalize an HTTPS URL.
    """
    if not isinstance(input_url, str):
        raise ValueError("URL must be a string")
    url = input_url.strip()
    if not url:
        raise ValueError("URL must not be empty")
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("URL exceeds maximum allowed length")
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS scheme is allowed")
    if not parsed.netloc:
        raise ValueError("URL must include a network location (host)")
    # Normalize: remove fragments
    normalized = parsed._replace(fragment="").geturl()
    return normalized


def is_allowed_by_robots(url: str, user_agent: str = USER_AGENT, timeout: float = DEFAULT_CONNECT_TIMEOUT) -> bool:
    """
    Check robots.txt to ensure scraping is allowed for the provided user agent.
    """
    parsed = urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = robotparser.RobotFileParser()
    # robotparser.read() uses urllib which respects HTTPS certificate validation in modern Python
    rp.set_url(robots_url)
    try:
        # Use a manual fetch with requests to enforce strict TLS and timeouts, then feed data to robotparser.
        headers = {"User-Agent": user_agent}
        resp = requests.get(robots_url, headers=headers, timeout=(timeout, timeout), allow_redirects=True)
        if not resp.ok or not resp.text:
            # If robots.txt is unavailable, default to allowed as per standard practice.
            rp.parse([])
        else:
            # Ensure final URL after redirects remains HTTPS
            final_scheme = urlparse(resp.url).scheme.lower()
            if final_scheme != "https":
                # Downgrade to HTTP is not allowed
                return False
            # Limit robots.txt size to a reasonable amount to avoid memory abuse
            text = resp.text
            if len(text) > 200_000:  # 200 KB safety cap
                text = text[:200_000]
            rp.parse(text.splitlines())
    except requests.RequestException:
        # On network errors fetching robots.txt, default to allowed
        rp.parse([])
    return rp.can_fetch(user_agent, url)


def check_tls_certificate(hostname: str, port: int = 443, timeout: float = DEFAULT_CONNECT_TIMEOUT) -> None:
    """
    Establish a TLS connection with strict hostname verification and certificate validation.
    This checks:
    - Proper certificate chain validation against system CAs
    - Hostname verification
    - Certificate validity period (expiration)
    Note: Revocation (OCSP/CRL) checking is not performed here due to library limitations.
    """
    if not hostname or len(hostname) > 255:
        raise ValueError("Invalid hostname for TLS check")
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # Disable weak protocols
    if hasattr(ssl, "OP_NO_SSLv2"):
        context.options |= ssl.OP_NO_SSLv2
    if hasattr(ssl, "OP_NO_SSLv3"):
        context.options |= ssl.OP_NO_SSLv3
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        context.options |= ssl.OP_NO_COMPRESSION
    # Prefer secure ciphers by default (relies on system defaults)
    with closing(socket.create_connection((hostname, port), timeout=timeout)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Handshake occurs on wrap; if it fails, an exception is raised.
            _ = ssock.version()
            # Certificate validity (expiration) is validated during handshake;
            # additional checks could be added here if needed.


def fetch_https_content(
    url: str,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = DEFAULT_READ_TIMEOUT,
    user_agent: str = USER_AGENT,
) -> Tuple[str, bytes, str]:
    """
    Fetch content from the given HTTPS URL securely, returning:
    - final_url (after redirects),
    - content bytes,
    - content_type header value (lowercased).
    """
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.7",
        "Connection": "close",
    }
    # Pre-flight TLS certificate validation using separate TLS handshake
    parsed = urlparse(url)
    check_tls_certificate(parsed.hostname or "", 443)

    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=(connect_timeout, read_timeout),
            allow_redirects=True,
        )
    except requests.RequestException as ex:
        raise RuntimeError(f"Network error when fetching URL: {ex}") from ex

    if resp is None:
        raise RuntimeError("No response received")
    # Enforce HTTPS after redirects
    final_url = resp.url
    if urlparse(final_url).scheme.lower() != "https":
        raise RuntimeError("Redirected to a non-HTTPS URL; blocking for security")

    # Limit content size to avoid memory issues (e.g., 5 MB)
    content = resp.content if len(resp.content) <= 5_000_000 else resp.content[:5_000_000]
    content_type = resp.headers.get("Content-Type", "").lower()
    return final_url, content, content_type


def parse_html(url: str, content: bytes, content_type: str) -> PageData:
    """
    Parse HTML content to extract page metadata and links.
    """
    if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
        raise ValueError("Unsupported content type for HTML parsing")
    # Decode using requests' apparent encoding fallback is not here; we'll try utf-8 then fallback.
    text: str
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        text = content.decode("latin-1", errors="replace")

    soup = BeautifulSoup(text, "html.parser")
    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else None

    description = None
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc and meta_desc.has_attr("content"):
        description = str(meta_desc["content"]).strip()[:500]

    # Extract links
    links: List[Tuple[str, Optional[str]]] = []
    for a in soup.find_all("a"):
        href = a.get("href")
        if not href or not isinstance(href, str):
            continue
        abs_url = urljoin(url, href.strip())
        # Validate link is HTTPS and reasonably sized
        try:
            abs_url_valid = validate_url(abs_url)
        except ValueError:
            continue
        anchor_text = a.get_text(strip=True) if a else None
        links.append((abs_url_valid, anchor_text if anchor_text else None))
        if len(links) >= MAX_LINKS_STORED:
            break

    fetched_at_utc_iso = datetime.now(timezone.utc).isoformat()
    return PageData(url=url, fetched_at_utc_iso=fetched_at_utc_iso, title=title, description=description, links=links)


def init_db(db_path: str) -> None:
    """
    Initialize the SQLite database with necessary tables.
    """
    if not isinstance(db_path, str) or not db_path:
        raise ValueError("Invalid database path")
    with sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                fetched_at TEXT NOT NULL,
                title TEXT,
                description TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_id INTEGER NOT NULL,
                link_url TEXT NOT NULL,
                anchor_text TEXT,
                UNIQUE(page_id, link_url),
                FOREIGN KEY(page_id) REFERENCES pages(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_links_url ON links(link_url);")


def store_page_data(db_path: str, page: PageData) -> Dict[str, Any]:
    """
    Store page metadata and links into the database safely.
    Returns a summary dict with counts.
    """
    if not isinstance(db_path, str) or not db_path:
        raise ValueError("Invalid database path")
    link_rows_added = 0
    with sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
        conn.execute("PRAGMA foreign_keys=ON;")
        # Upsert page
        conn.execute(
            """
            INSERT INTO pages(url, fetched_at, title, description)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                fetched_at=excluded.fetched_at,
                title=excluded.title,
                description=excluded.description;
            """,
            (page.url, page.fetched_at_utc_iso, page.title, page.description),
        )
        cur = conn.execute("SELECT id FROM pages WHERE url = ?;", (page.url,))
        row = cur.fetchone()
        if not row:
            raise RuntimeError("Failed to retrieve page id after insert")
        page_id = int(row[0])

        # Insert links (ignore duplicates)
        for link_url, anchor_text in page.links:
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO links(page_id, link_url, anchor_text)
                    VALUES (?, ?, ?);
                    """,
                    (page_id, link_url, anchor_text),
                )
                link_rows_added += conn.total_changes  # total since last commit/connection; not perfect per-row
            except sqlite3.Error:
                # Ignore malformed anchor_text or url issues at DB level
                continue

    return {
        "page_url": page.url,
        "title": page.title,
        "description": page.description,
        "links_extracted": len(page.links),
        "links_insert_attempted": len(page.links),
        "db_link_changes": link_rows_added,
    }


def scrape_and_store(
    url: str,
    db_path: str,
    require_robots_allow: bool = True,
) -> Dict[str, Any]:
    """
    Orchestrates validation, robots check, secure fetch, parse, and store.
    Returns a summary dict.
    """
    normalized = validate_url(url)
    if require_robots_allow and not is_allowed_by_robots(normalized, USER_AGENT):
        raise PermissionError("Fetching is disallowed by robots.txt")

    final_url, content, content_type = fetch_https_content(normalized)
    page_data = parse_html(final_url, content, content_type)
    init_db(db_path)
    summary = store_page_data(db_path, page_data)
    return summary


def _print_summary(i: int, url: str, result: Optional[Dict[str, Any]], error: Optional[Exception]) -> None:
    """
    Helper to print concise test results without exposing sensitive data.
    """
    if error is not None:
        print(f"[{i}] URL: {url} -> ERROR: {type(error).__name__}: {str(error)[:200]}")
    else:
        safe_title = (result.get("title") or "")[:80] if result else ""
        print(
            f"[{i}] URL: {url} -> OK | title='{safe_title}' | links_extracted={result.get('links_extracted', 0)}"
        )


def main() -> None:
    """
    Run 5 test cases.
    Note: Network access is required. Tests use public HTTPS pages.
    """
    test_db = "scraper.db"
    tests = [
        "https://example.com/",
        "https://httpbin.org/html",
        "https://www.python.org/",
        "https://www.wikipedia.org/",
        "https://www.iana.org/domains/reserved",
    ]
    for idx, turl in enumerate(tests, start=1):
        try:
            result = scrape_and_store(turl, test_db, require_robots_allow=True)
            _print_summary(idx, turl, result, None)
        except Exception as ex:
            _print_summary(idx, turl, None, ex)


if __name__ == "__main__":
    main()