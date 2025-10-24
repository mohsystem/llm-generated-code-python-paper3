
import sys
import sqlite3
import urllib.request
import urllib.error
import ssl
import re
from html.parser import HTMLParser
from typing import List, Tuple, Optional
from pathlib import Path


class SecureHTMLParser(HTMLParser):
    """\n    Secure HTML parser that extracts text content without executing scripts.\n    Validates and sanitizes all extracted data.\n    """
    def __init__(self):
        super().__init__()
        self.data: List[str] = []
        self.max_data_length = 1000000  # Prevent excessive memory usage
        self.current_length = 0
    
    def handle_data(self, data: str) -> None:
        """\n        Extract text data with size limits to prevent DoS.\n        """
        # Validate data is a string
        if not isinstance(data, str):
            return
        
        # Strip and validate length
        cleaned = data.strip()
        if not cleaned:
            return
        
        # Prevent excessive memory usage
        if self.current_length + len(cleaned) > self.max_data_length:
            return
        
        # Sanitize: remove control characters except whitespace
        sanitized = re.sub(r'[\\x00-\\x08\\x0B-\\x0C\\x0E-\\x1F\\x7F]', '', cleaned)
        
        if sanitized:
            self.data.append(sanitized)
            self.current_length += len(sanitized)


def validate_url(url: str) -> bool:
    """\n    Validate URL format and ensure it uses HTTPS only.\n    Prevents injection and ensures secure protocol.\n    """
    if not isinstance(url, str):
        return False
    
    # Check length to prevent DoS
    if len(url) > 2048:
        return False
    
    # Must start with https:// (no http://)
    if not url.startswith('https://'):
        return False
    
    # Basic format validation using regex
    url_pattern = re.compile(
        r'^https://'  # Must start with https://
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*'  # Domain parts
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'  # Final domain part
        r'(?::[0-9]{1,5})?'  # Optional port
        r'(?:/[^\\s]*)?$'  # Optional path
    )
    
    return bool(url_pattern.match(url))


def create_secure_ssl_context() -> ssl.SSLContext:
    """\n    Create SSL context with secure TLS settings.\n    Enforces certificate validation and modern TLS versions.\n    """
    # Create default context with certificate verification enabled
    ctx = ssl.create_default_context()
    
    # Enforce certificate validation (CWE-295, CWE-297)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    
    # Force TLS 1.2 or higher (CWE-327)
    if hasattr(ssl, "TLSVersion"):  # Python 3.10+
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    else:  # Older Python versions
        # Disable insecure protocols
        ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
    
    return ctx


def scrape_website(url: str) -> Optional[List[str]]:
    """\n    Scrape data from a website using secure HTTPS connection.\n    Validates URL, enforces TLS, and limits response size.\n    """
    # Validate URL format and protocol (CWE-20)
    if not validate_url(url):
        print("Error: Invalid URL. Must be HTTPS and properly formatted.", file=sys.stderr)
        return None
    
    try:
        # Create secure SSL context (CWE-295, CWE-297, CWE-327)
        ssl_context = create_secure_ssl_context()
        
        # Set timeout to prevent hanging
        timeout = 30
        
        # Set maximum response size to prevent DoS (CWE-400)
        max_size = 10 * 1024 * 1024  # 10 MB limit
        
        # Create request with secure headers
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'SecureScraper/1.0',
                'Accept': 'text/html',
            }
        )
        
        # Open connection with SSL context
        with urllib.request.urlopen(req, context=ssl_context, timeout=timeout) as response:
            # Validate response code
            if response.status != 200:
                print(f"Error: HTTP {response.status}", file=sys.stderr)
                return None
            
            # Read response with size limit (CWE-400)
            content = response.read(max_size)
            
            # Check if we hit the size limit
            if len(content) >= max_size:
                print("Warning: Response truncated at size limit", file=sys.stderr)
            
            # Decode with proper encoding
            html_content = content.decode('utf-8', errors='ignore')
        
        # Parse HTML securely (prevents XSS, code injection)
        parser = SecureHTMLParser()
        parser.feed(html_content)
        
        return parser.data
    
    except urllib.error.URLError as e:
        print(f"Error fetching URL: {e.reason}", file=sys.stderr)
        return None
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code}", file=sys.stderr)
        return None
    except ssl.SSLError as e:
        print(f"SSL Error: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Unexpected error: {type(e).__name__}", file=sys.stderr)
        return None
def validate_db_path(db_path: str) -> bool:
    """
    Validate database path to prevent path traversal attacks.
    Ensures path is within expected directory.
    """
    if not isinstance(db_path, str):
        return False

    # Check length
    if len(db_path) > 255:
        return False

    # Resolve to absolute path
    try:
        base_dir = Path.cwd()
        target_path = (base_dir / db_path).resolve()

        # Ensure path is within base directory (CWE-22)
        if not str(target_path).startswith(str(base_dir)):
            return False

        # Ensure it's not a directory
        if target_path.exists() and target_path.is_dir():
            return False

        # Ensure parent directory exists
        if not target_path.parent.exists():
            return False

        return True
    except (ValueError, OSError):
        return False


def store_in_database(data: List[str], db_path: str, source_url: str) -> bool:
    """
    Store scraped data in SQLite database with parameterized queries.
    Prevents SQL injection and validates all inputs.
    """
    # Validate database path (CWE-22)
    if not validate_db_path(db_path):
        print("Error: Invalid database path", file=sys.stderr)
        return False

    # Validate inputs
    if not isinstance(data, list) or not data:
        print("Error: Invalid data format", file=sys.stderr)
        return False

    if not isinstance(source_url, str) or len(source_url) > 2048:
        print("Error: Invalid source URL", file=sys.stderr)
        return False

    connection: Optional[sqlite3.Connection] = None

    try:
        # Connect to database with secure settings
        connection = sqlite3.connect(
            db_path,
            timeout=10.0,
            isolation_level='DEFERRED'
        )

        cursor = connection.cursor()

        # Create table with proper schema
        # Using parameterized queries prevents SQL injection (CWE-89)
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS scraped_data (
                                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                        source_url TEXT NOT NULL,
                                                        content TEXT NOT NULL,
                                                        scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            '''
        )

        # Create index for performance
        cursor.execute(
            '''
            CREATE INDEX IF NOT EXISTS idx_source_url
                ON scraped_data(source_url)
            '''
        )

        # Insert data using parameterized queries (CWE-89)
        for item in data:
            # Validate each item
            if not isinstance(item, str):
                continue

            # Limit item length to prevent excessive storage
            if len(item) > 50000:
                item = item[:50000]

            # Use parameterized query to prevent SQL injection
            cursor.execute(
                'INSERT INTO scraped_data (source_url, content) VALUES (?, ?)',
                (source_url, item)
            )

        # Commit transaction
        connection.commit()

        print(f"Successfully stored {len(data)} items in database")
        return True

    except sqlite3.Error as e:
        print(f"Database error: {type(e).__name__}", file=sys.stderr)
        if connection:
            connection.rollback()
        return False
    except Exception as e:
        print(f"Unexpected error: {type(e).__name__}", file=sys.stderr)
        if connection:
            connection.rollback()
        return False
    finally:
        # Ensure connection is closed (CWE-404)
        if connection:
            connection.close()


def main() -> int:
    """
    Main function with test cases demonstrating secure web scraping.
    """
    print("=== Secure Web Scraper Test Cases ===\n")

    # Test case 1: Valid HTTPS URL (example.com)
    print("Test 1: Scraping from example.com...")
    url1 = "https://example.com"
    data1 = scrape_website(url1)
    if data1:
        result1 = store_in_database(data1, "test_data1.db", url1)
        print(f"Result: {'Success' if result1 else 'Failed'}\n")
    else:
        print("Result: Failed to scrape\n")

    # Test case 2: Invalid URL - HTTP instead of HTTPS (should fail)
    print("Test 2: Testing HTTP URL (should reject)...")
    url2 = "http://example.com"
    data2 = scrape_website(url2)
    print(f"Result: {'Rejected' if data2 is None else 'Failed - should reject HTTP'}\n")

    # Test case 3: Invalid URL - malformed (should fail)
    print("Test 3: Testing malformed URL (should reject)...")
    url3 = "not-a-valid-url"
    data3 = scrape_website(url3)
    print(f"Result: {'Rejected' if data3 is None else 'Failed - should reject malformed'}\n")

    # Test case 4: Path traversal attempt in database path (should fail)
    print("Test 4: Testing path traversal in DB path (should reject)...")
    url4 = "https://example.com"
    data4 = ["test data"]
    result4 = store_in_database(data4, "../etc/passwd", url4)
    print(f"Result: {'Rejected' if not result4 else 'Failed - should reject traversal'}\n")

    # Test case 5: Valid scrape and store
    print("Test 5: Complete scrape and store operation...")
    url5 = "https://www.ietf.org"
    data5 = scrape_website(url5)
    if data5:
        result5 = store_in_database(data5, "test_data5.db", url5)
        print(f"Result: {'Success' if result5 else 'Failed'}\n")
    else:
        print("Result: Failed to scrape\n")

    print("=== Test Cases Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
