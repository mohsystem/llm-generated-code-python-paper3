import sqlite3
import re
from typing import Optional

# To run, first install the 'requests' library:
# pip install requests
import requests

def parse_title(html: str) -> str:
    """
    Extracts the content of the first <h1> tag from an HTML string.
    A simple regex is used; for complex pages, a library like BeautifulSoup is recommended.
    """
    # Using a case-insensitive regex to find content within <h1> tags.
    match = re.search(r'<h1.*?>(.*?)</h1>', html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()
    return "No H1 Title Found"

def initialize_database(db_path: str) -> None:
    """Initializes the database and creates the 'pages' table if it doesn't exist."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def scrape_and_store(url: str, db_path: str) -> bool:
    """
    Scrapes a website, extracts the H1 title, and stores it in a SQLite database.
    
    Args:
        url: The URL of the website to scrape.
        db_path: The path to the SQLite database file.

    Returns:
        True if successful, False otherwise.
    """
    try:
        # 1. Fetch website content securely
        # requests handles SSL/TLS verification by default.
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)

        html_body = response.text

        # 2. Parse the data
        title = parse_title(html_body)

        # 3. Store data in the database
        # Using a context manager for the connection ensures it's closed properly.
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            # Using parameterized query to prevent SQL injection
            # INSERT OR REPLACE will update the title if the URL already exists
            cursor.execute(
                "INSERT OR REPLACE INTO pages (url, title) VALUES (?, ?)",
                (url, title)
            )
            conn.commit()
            print(f"Successfully scraped and stored: {url}")
            return True

    except requests.exceptions.RequestException as e:
        print(f"An error occurred during scraping {url}: {e}")
        return False
    except sqlite3.Error as e:
        print(f"Database error for {url}: {e}")
        return False

def main():
    """Main function to run test cases."""
    db_file = "scraped_data_python.db"
    initialize_database(db_file)

    urls_to_scrape = [
        "https://example.com/",
        "https://www.iana.org/domains/example",
        "https://httpbin.org/html",
        "http://info.cern.ch/hypertext/WWW/TheProject.html",
        "https://www.w3.org/TR/html52/"
    ]
    
    print("--- Starting Web Scraping Tests ---")
    success_count = 0
    for url in urls_to_scrape:
        print(f"Processing: {url}")
        if scrape_and_store(url, db_file):
            success_count += 1
        print("--------------------")

    print("--- Scraping Finished ---")
    print(f"{success_count} out of {len(urls_to_scrape)} pages scraped successfully.")
    print(f"Data stored in '{db_file}'")

if __name__ == "__main__":
    main()