import sqlite3
import requests
from bs4 import BeautifulSoup
import validators

# Note: This code requires external packages.
# Install them using pip:
# pip install requests beautifulsoup4 validators

def scrape_and_store(url: str, db_path: str):
    """
    Scrapes the title and the first H1 tag from a given URL and stores it in a local SQLite database.

    Args:
        url (str): The URL to scrape.
        db_path (str): The path to the SQLite database file.
    """
    # 1. Security: Validate URL to prevent requests to local/unexpected schemes
    if not validators.url(url):
        print(f"Error: Invalid URL provided: {url}")
        return

    db_conn = None
    try:
        # 2. Security: Set a reasonable timeout to prevent denial-of-service attacks
        #    Use a proper User-Agent to identify the scraper.
        headers = {
            'User-Agent': 'My-Secure-Scraper/1.0 (https://my-scraper-website.com/info)'
        }
        response = requests.get(url, timeout=10, headers=headers)
        # Raise an exception for bad status codes (4xx or 5xx)
        response.raise_for_status()

        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract data. .text will strip HTML tags, preventing stored XSS.
        title = soup.title.text.strip() if soup.title else "No title found"
        h1 = soup.find('h1')
        h1_content = h1.text.strip() if h1 else "No H1 tag found"

        # Connect to SQLite database
        db_conn = sqlite3.connect(db_path)
        cursor = db_conn.cursor()

        # Create table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scraped_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                title TEXT,
                h1_content TEXT
            )
        ''')

        # 3. Security: Use parameterized queries to prevent SQL injection.
        # The '?' placeholder ensures that user-controlled data is treated as a value, not an SQL command.
        cursor.execute('''
            INSERT OR REPLACE INTO scraped_data (url, title, h1_content)
            VALUES (?, ?, ?)
        ''', (url, title, h1_content))

        db_conn.commit()
        print(f"Successfully scraped and stored data from: {url}")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        if db_conn:
            db_conn.rollback()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if db_conn:
            db_conn.close()


if __name__ == '__main__':
    DB_FILE = "scraped_data_python.db"

    # 5 Test Cases
    test_urls = [
        "http://example.com",
        "https://www.python.org/psf/",
        "https://www.djangoproject.com/",
        "https://github.com/",
        "http://invalid.url.that.does.not.exist.xyz/" # Test failure case
    ]

    for test_url in test_urls:
        scrape_and_store(test_url, DB_FILE)
        print("---------------------------------")