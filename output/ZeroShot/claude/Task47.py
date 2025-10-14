
import sqlite3
import urllib.request
import urllib.error
import re
from datetime import datetime
from urllib.parse import urlparse

class Task47:
    def __init__(self, db_name="scraped_data.db"):
        self.db_name = db_name
    
    def scrape_and_store(self, url, table_name):
        try:
            # Validate URL
            if not self.is_valid_url(url):
                print("Invalid URL provided")
                return
            
            # Initialize database
            self.initialize_database(table_name)
            
            # Scrape data
            content = self.scrape_website(url)
            
            # Store in database
            self.store_data(table_name, url, content)
            
            print("Data scraped and stored successfully")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
        except:
            return False
    
    def initialize_database(self, table_name):
        table_name = self.sanitize_table_name(table_name)
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute(f'''\n            CREATE TABLE IF NOT EXISTS {table_name} (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                url TEXT NOT NULL,\n                content TEXT,\n                scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n            )\n        ''')
        
        conn.commit()
        conn.close()
    
    def sanitize_table_name(self, name):
        return re.sub(r'[^a-zA-Z0-9_]', '_', name)
    
    def scrape_website(self, url):
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            content = response.read().decode('utf-8')
        
        return content
    
    def store_data(self, table_name, url, content):
        table_name = self.sanitize_table_name(table_name)
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute(
            f"INSERT INTO {table_name} (url, content) VALUES (?, ?)",
            (url, content)
        )
        
        conn.commit()
        conn.close()

def main():
    print("=== Web Scraper Test Cases ===\\n")
    scraper = Task47()
    
    # Test Case 1: Valid URL
    print("Test 1: Scraping example.com")
    scraper.scrape_and_store("http://example.com", "test_data")
    
    # Test Case 2: Invalid URL
    print("\\nTest 2: Invalid URL")
    scraper.scrape_and_store("invalid-url", "test_data")
    
    # Test Case 3: HTTPS URL
    print("\\nTest 3: HTTPS URL")
    scraper.scrape_and_store("https://example.com", "secure_data")
    
    # Test Case 4: Different table name
    print("\\nTest 4: Different table")
    scraper.scrape_and_store("http://example.com", "website_content")
    
    # Test Case 5: Special characters in table name
    print("\\nTest 5: Table name sanitization")
    scraper.scrape_and_store("http://example.com", "data-table-2024")

if __name__ == "__main__":
    main()
