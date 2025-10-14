# Dependencies: requests, beautifulsoup4
# How to run:
# 1. pip install requests beautifulsoup4
# 2. python your_script_name.py

import sqlite3
import requests
from bs4 import BeautifulSoup

DB_PATH = "scraping_results_python.db"

def setup_database(db_path):
    """Creates the database and table if they don't exist."""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor.execute(create_table_sql)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database setup error: {e}")
    finally:
        if conn:
            conn.close()

def scrape_and_store(url, db_path):
    """Scrapes a website, extracts its title, and stores it in the database."""
    print(f"Scraping: {url}")
    try:
        # 1. Fetch HTML content
        headers = {'User-Agent': 'Python-Scraper-Bot/1.0'}
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        # 2. Parse HTML and extract title using BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else None

        if not title:
            print(f"Could not find title for URL: {url}")
            return
        
        title = title.strip()

        # 3. Store data in the database
        conn = None
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            # Use a parameterized query to prevent SQL injection
            insert_sql = "INSERT OR IGNORE INTO pages(url, title) VALUES(?, ?)"
            cursor.execute(insert_sql, (url, title))
            conn.commit()
            print(f"Successfully stored title: \"{title}\"")
        except sqlite3.Error as e:
            print(f"Database insertion error: {e}")
        finally:
            if conn:
                conn.close()

    except requests.exceptions.RequestException as e:
        print(f"Error during scraping of {url}: {e}")

def print_database_contents(db_path):
    """Prints all records from the 'pages' table."""
    print("\n--- Database Contents ---")
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, url, title, scraped_at FROM pages")
        rows = cursor.fetchall()
        for row in rows:
            print(f"{row[0]}\t{row[1]}\t{row[2]}\t{row[3]}")
    except sqlite3.Error as e:
        print(f"Database query error: {e}")
    finally:
        if conn:
            conn.close()
    print("-------------------------\n")


if __name__ == "__main__":
    setup_database(DB_PATH)
    
    test_urls = [
        "http://books.toscrape.com/",
        "http://books.toscrape.com/catalogue/category/books/travel_2/index.html",
        "http://books.toscrape.com/catalogue/a-light-in-the-attic_1000/index.html",
        "http://quotes.toscrape.com/",
        "http://quotes.toscrape.com/tag/humor/"
    ]

    for url in test_urls:
        scrape_and_store(url, DB_PATH)
        
    print_database_contents(DB_PATH)