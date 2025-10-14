import re
import sqlite3
import sys
import urllib.request
import time

def scrape_and_store(url: str, db_path: str) -> int:
    html = fetch_url(url)
    title = extract_title(html)
    links = extract_links(html)
    inserted = store_to_sqlite(db_path, url, title, links)
    return inserted

def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Task47Bot/1.0 (+https://example.org)"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    try:
        return data.decode('utf-8', errors='ignore')
    except:
        return data.decode('latin-1', errors='ignore')

def extract_title(html: str) -> str:
    m = re.search(r"(?is)<title\b[^>]*>(.*?)</title>", html)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return ""

def extract_links(html: str):
    links = []
    for m in re.finditer(r"(?is)<a\b[^>]*href\s*=\s*(['\"])(.*?)\1[^>]*>(.*?)</a>", html):
        href = m.group(2).strip()
        text = re.sub(r"<[^>]+>", "", m.group(3))
        text = re.sub(r"\s+", " ", text).strip()
        links.append((href, text))
    return links

def store_to_sqlite(db_path: str, url: str, title: str, links) -> int:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS pages (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, title TEXT, fetched_at TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS links (id INTEGER PRIMARY KEY AUTOINCREMENT, page_id INTEGER, href TEXT, text TEXT, FOREIGN KEY(page_id) REFERENCES pages(id))")
        fetched_at = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        cur.execute("INSERT INTO pages(url, title, fetched_at) VALUES (?,?,?)", (url, title, fetched_at))
        page_id = cur.lastrowid
        cur.executemany("INSERT INTO links(page_id, href, text) VALUES (?,?,?)",
                        [(page_id, href, text) for href, text in links])
        conn.commit()
        return len(links)
    finally:
        conn.close()

if __name__ == "__main__":
    db_path = "scrape_python.db"
    test_urls = [
        "https://example.com",
        "https://www.wikipedia.org",
        "https://www.python.org",
        "https://www.gnu.org",
        "https://www.rfc-editor.org"
    ]
    for u in test_urls:
        try:
            n = scrape_and_store(u, db_path)
            print(f"Python: Inserted {n} links from {u} into {db_path}")
        except Exception as e:
            print(f"Python: Failed for {u} -> {e}", file=sys.stderr)