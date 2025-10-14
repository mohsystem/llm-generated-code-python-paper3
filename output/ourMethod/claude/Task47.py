
import re
import hashlib
import sqlite3
import time
import urllib.request
import urllib.error
import ssl
from typing import Optional, List, Tuple
from dataclasses import dataclass
from pathlib import Path

MAX_URL_LENGTH: int = 2048
MAX_CONTENT_LENGTH: int = 10485760  # 10MB
CONNECT_TIMEOUT: int = 10
URL_PATTERN: re.Pattern = re.compile(
    r'^https://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[a-zA-Z0-9._~:/?#\\[\\]@!$&\'()*\+,;=-]*)?$'
)

@dataclass
class ScrapedData:
    url: str
    content: str
    content_hash: str
    timestamp: int

def validate_and_normalize_url(url: str) -> str:
    """Validate and normalize URL ensuring it's HTTPS only."""
    if not url or not isinstance(url, str):
        raise ValueError("URL cannot be empty or non-string")
    
    trimmed = url.strip()
    if len(trimmed) > MAX_URL_LENGTH:
        raise ValueError("URL exceeds maximum length")
    
    if not URL_PATTERN.match(trimmed):
        raise ValueError("Invalid URL format. Only HTTPS URLs are allowed")
    
    return trimmed

def scrape_website(url: str) -> str:
    """Scrape content from a website with security validations."""
    url = validate_and_normalize_url(url)
    
    # Create SSL context with certificate verification
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    request = urllib.request.Request(
        url,
        headers={'User-Agent': 'SecureScraper/1.0'}
    )
    
    try:
        with urllib.request.urlopen(
            request,
            timeout=CONNECT_TIMEOUT,
            context=context
        ) as response:
            
            if response.status != 200:
                raise IOError(f"HTTP error code: {response.status}")
            
            content_type = response.headers.get('Content-Type', '')
            if 'text' not in content_type.lower():
                raise IOError("Invalid content type")
            
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > MAX_CONTENT_LENGTH:
                raise IOError("Content exceeds maximum allowed size")
            
            content = b''
            chunk_size = 8192
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                content += chunk
                if len(content) > MAX_CONTENT_LENGTH:
                    raise IOError("Content exceeds maximum allowed size")
            
            return content.decode('utf-8', errors='replace')
            
    except urllib.error.URLError as e:
        raise IOError(f"Failed to fetch URL: {str(e)}")

def calculate_hash(content: str) -> str:
    """Calculate SHA-256 hash of content."""
    if content is None:
        raise ValueError("Content cannot be None")
    
    hash_obj = hashlib.sha256()
    hash_obj.update(content.encode('utf-8'))
    return hash_obj.hexdigest()

def initialize_database(db_path: str) -> sqlite3.Connection:
    """Initialize SQLite database with proper schema."""
    if not db_path or not isinstance(db_path, str):
        raise ValueError("Database path cannot be empty or non-string")
    
    if not re.match(r'^[a-zA-Z0-9_./:-]+\\.db$', db_path):
        raise ValueError("Invalid database path format")
    
    conn = sqlite3.connect(db_path, isolation_level='DEFERRED')
    cursor = conn.cursor()
    
    cursor.execute('''\n        CREATE TABLE IF NOT EXISTS scraped_data (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            url TEXT NOT NULL,\n            content TEXT NOT NULL,\n            content_hash TEXT NOT NULL,\n            timestamp INTEGER NOT NULL\n        )\n    ''')
    
    conn.commit()
    return conn

def store_data(conn: sqlite3.Connection, data: ScrapedData) -> None:
    """Store scraped data in database using parameterized queries."""
    if conn is None or data is None:
        raise ValueError("Connection and data cannot be None")
    
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO scraped_data (url, content, content_hash, timestamp) VALUES (?, ?, ?, ?)',
        (data.url, data.content, data.content_hash, data.timestamp)
    )
    conn.commit()

def retrieve_data(conn: sqlite3.Connection, url: Optional[str] = None) -> List[ScrapedData]:
    """Retrieve scraped data from database."""
    if conn is None:
        raise ValueError("Connection cannot be None")
    
    cursor = conn.cursor()
    
    if url:
        cursor.execute(
            'SELECT url, content, content_hash, timestamp FROM scraped_data WHERE url = ? ORDER BY timestamp DESC',
            (url,)
        )
    else:
        cursor.execute(
            'SELECT url, content, content_hash, timestamp FROM scraped_data ORDER BY timestamp DESC'
        )
    
    results = []
    for row in cursor.fetchall():
        results.append(ScrapedData(
            url=row[0],
            content=row[1],
            content_hash=row[2],
            timestamp=row[3]
        ))
    
    return results

def main() -> None:
    """Main function with test cases."""
    print("=== Web Scraper with Local Database - Test Cases ===\\n")
    
    # Test Case 1: Initialize database
    print("Test 1: Initialize database")
    conn = None
    try:
        conn = initialize_database("test_scraper.db")
        print("✓ Database initialized successfully\\n")
    except Exception as e:
        print(f"✗ Error: {str(e)}\\n")
    
    # Test Case 2: Validate URL - valid HTTPS
    print("Test 2: Validate valid HTTPS URL")
    try:
        valid_url = "https://example.com/page"
        normalized = validate_and_normalize_url(valid_url)
        print(f"✓ Valid URL accepted: {normalized}\\n")
    except Exception as e:
        print(f"✗ Error: {str(e)}\\n")
    
    # Test Case 3: Validate URL - reject HTTP
    print("Test 3: Reject insecure HTTP URL")
    try:
        insecure_url = "http://example.com/page"
        validate_and_normalize_url(insecure_url)
        print("✗ Should have rejected HTTP URL\\n")
    except ValueError as e:
        print(f"✓ HTTP URL correctly rejected: {str(e)}\\n")
    except Exception as e:
        print(f"✗ Unexpected error: {str(e)}\\n")
    
    # Test Case 4: Calculate hash
    print("Test 4: Calculate content hash")
    try:
        content = "Sample content for hashing"
        content_hash = calculate_hash(content)
        print(f"✓ Hash calculated: {content_hash}\\n")
    except Exception as e:
        print(f"✗ Error: {str(e)}\\n")
    
    # Test Case 5: Store and retrieve data
    print("Test 5: Store and retrieve data")
    if conn:
        try:
            test_url = "https://example.com/test"
            test_content = "Test content"
            test_hash = calculate_hash(test_content)
            timestamp = int(time.time())
            
            data = ScrapedData(test_url, test_content, test_hash, timestamp)
            store_data(conn, data)
            print("✓ Data stored successfully")
            
            retrieved = retrieve_data(conn, test_url)
            if retrieved and retrieved[0].url == test_url:
                print(f"✓ Data retrieved successfully: {len(retrieved)} record(s)\\n")
            else:
                print("✗ Data retrieval mismatch\\n")
        except Exception as e:
            print(f"✗ Error: {str(e)}\\n")
        finally:
            if conn:
                conn.close()
            try:
                Path("test_scraper.db").unlink(missing_ok=True)
            except Exception as e:
                print(f"Cleanup error: {str(e)}")
    
    print("=== All tests completed ===")

if __name__ == "__main__":
    main()
