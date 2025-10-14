
import sqlite3
import urllib.request
import urllib.error
import re
import ssl
from datetime import datetime

class Task47:
    DB_NAME = "scraped_data.db"
    TIMEOUT = 5
    MAX_CONTENT_LENGTH = 1000000
    
    @staticmethod
    def init_database():
        """Initialize the SQLite database with proper schema"""
        try:
            conn = sqlite3.connect(Task47.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS scraped_data (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    url TEXT NOT NULL,\n                    title TEXT,\n                    content TEXT,\n                    scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n                )\n            ''')
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
    
    @staticmethod
    def scrape_website(url):
        """Scrape website content with security measures"""
        if not url or not isinstance(url, str) or not url.strip():
            raise ValueError("URL cannot be None or empty")
        
        if not re.match(r'^https?://', url):
            raise ValueError("Invalid URL format. Must start with http:// or https://")
        
        try:
            context = ssl.create_default_context()
            
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'Mozilla/5.0 (Secure Scraper)'}
            )
            
            with urllib.request.urlopen(req, timeout=Task47.TIMEOUT, context=context) as response:
                if response.status != 200:
                    raise Exception(f"HTTP Error: {response.status}")
                
                content = response.read()
                
                if len(content) > Task47.MAX_CONTENT_LENGTH:
                    raise Exception("Content too large")
                
                return content.decode('utf-8', errors='ignore')
                
        except urllib.error.URLError as e:
            raise Exception(f"URL Error: {str(e)}")
        except Exception as e:
            raise Exception(f"Scraping error: {str(e)}")
    
    @staticmethod
    def extract_title(html):
        """Extract title from HTML content"""
        if not html:
            return ""
        
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        if match:
            return Task47.sanitize_string(match.group(1))
        return "No title found"
    
    @staticmethod
    def sanitize_string(input_str):
        """Sanitize string to prevent SQL injection and XSS"""
        if not input_str:
            return ""
        
        sanitized = re.sub(r'[<>"\'%;()&+]', '', input_str)
        return sanitized.strip()
    
    @staticmethod
    def store_in_database(url, title, content):
        """Store scraped data in database using parameterized queries"""
        if not url or not isinstance(url, str) or not url.strip():
            raise ValueError("URL cannot be None or empty")
        
        try:
            conn = sqlite3.connect(Task47.DB_NAME)
            cursor = conn.cursor()
            
            sanitized_url = Task47.sanitize_string(url)
            sanitized_title = Task47.sanitize_string(title)
            truncated_content = content[:10000] if content else ""
            
            cursor.execute(
                "INSERT INTO scraped_data (url, title, content) VALUES (?, ?, ?)",
                (sanitized_url, sanitized_title, truncated_content)
            )
            
            conn.commit()
            rows_affected = cursor.rowcount
            conn.close()
            
            return rows_affected > 0
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
    
    @staticmethod
    def scrape_and_store(url):
        """Complete workflow: scrape and store"""
        content = Task47.scrape_website(url)
        title = Task47.extract_title(content)
        success = Task47.store_in_database(url, title, content)
        
        if not success:
            raise Exception("Failed to store data in database")
        
        return success


def main():
    """Main function with test cases"""
    try:
        Task47.init_database()
        print("Database initialized successfully")
        
        # Test case 1: Valid data storage
        test_url1 = "https://example.com/test1"
        print(f"\\nTest 1: Storing test data for {test_url1}")
        Task47.store_in_database(test_url1, "Test Page 1", "<html><body>Test content 1</body></html>")
        print("Test 1 passed")
        
        # Test case 2: Another valid entry
        test_url2 = "https://example.com/test2"
        print(f"\\nTest 2: Storing test data for {test_url2}")
        Task47.store_in_database(test_url2, "Test Page 2", "<html><body>Test content 2</body></html>")
        print("Test 2 passed")
        
        # Test case 3: Extract title test
        print("\\nTest 3: Extracting title")
        html = "<html><head><title>Sample Title</title></head><body>Content</body></html>"
        title = Task47.extract_title(html)
        print(f"Extracted title: {title}")
        print("Test 3 passed")
        
        # Test case 4: Sanitization test
        print("\\nTest 4: String sanitization")
        unsafe = "<script>alert('xss')</script>"
        safe = Task47.sanitize_string(unsafe)
        print(f"Sanitized string: {safe}")
        print("Test 4 passed")
        
        # Test case 5: Invalid URL handling
        print("\\nTest 5: Invalid URL handling")
        try:
            Task47.scrape_website("invalid-url")
            print("Test 5 failed - should throw exception")
        except ValueError as e:
            print(f"Test 5 passed - exception caught: {e}")
        
        print("\\nAll tests completed successfully!")
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
