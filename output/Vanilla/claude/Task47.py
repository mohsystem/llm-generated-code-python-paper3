
import sqlite3
import urllib.request
import re
from datetime import datetime

class Task47:
    DB_NAME = "scraped_data.db"
    
    @staticmethod
    def scrape_and_store(url):
        try:
            # Create database and table
            Task47.create_database()
            
            # Scrape website
            content = Task47.scrape_website(url)
            
            # Extract titles and links
            pattern = r'<a[^>]+href="([^"]*)"[^>]*>([^<]*)</a>'
            matches = re.findall(pattern, content)
            
            # Store in database
            conn = sqlite3.connect(Task47.DB_NAME)
            cursor = conn.cursor()
            
            for link, title in matches:
                cursor.execute(
                    "INSERT INTO scraped_data (url, title, content) VALUES (?, ?, ?)",
                    (link, title, content[:500])
                )
            
            conn.commit()
            conn.close()
            
            print(f"Data scraped and stored successfully from: {url}")
            
        except Exception as e:
            print(f"Error: {str(e)}")
    
    @staticmethod
    def create_database():
        conn = sqlite3.connect(Task47.DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS scraped_data (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                url TEXT,\n                title TEXT,\n                content TEXT,\n                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP\n            )\n        ''')
        conn.commit()
        conn.close()
    
    @staticmethod
    def scrape_website(url):
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
        return content

if __name__ == "__main__":
    print("Web Scraper Test Cases:")
    print("========================\\n")
    
    # Test case 1
    print("Test Case 1: Scraping example.com")
    Task47.scrape_and_store("http://example.com")
    
    # Test case 2
    print("\\nTest Case 2: Scraping example.org")
    Task47.scrape_and_store("http://example.org")
    
    # Test case 3
    print("\\nTest Case 3: Scraping example.net")
    Task47.scrape_and_store("http://example.net")
    
    # Test case 4
    print("\\nTest Case 4: Invalid URL test")
    Task47.scrape_and_store("http://invalid-url-that-does-not-exist-12345.com")
    
    # Test case 5
    print("\\nTest Case 5: Another valid URL")
    Task47.scrape_and_store("http://info.cern.ch")
