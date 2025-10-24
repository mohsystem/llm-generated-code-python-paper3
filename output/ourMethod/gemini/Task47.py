import sqlite3
import requests
import re
import logging
from bs4 import BeautifulSoup
from typing import Optional, List, Tuple
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

# --- Database Operations ---

def setup_database(db_path: str) -> bool:
    """
    Sets up the SQLite database and creates the 'books' table if it doesn't exist.

    Args:
        db_path (str): The path to the SQLite database file.

    Returns:
        bool: True if setup was successful, False otherwise.
    """
    # Rule #7: Ensure that all exceptions are caught and handled appropriately.
    # The 'with' statement ensures the connection is closed even if errors occur.
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            # Create table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS books (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    price REAL NOT NULL,
                    scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
        logging.info(f"Database setup successful at {db_path}")
        return True
    except sqlite3.Error as e:
        logging.error(f"Database setup error: {e}")
        return False

def store_data(db_path: str, data: List[Tuple[str, float]]) -> bool:
    """
    Stores a list of book data into the database using parameterized queries.

    Args:
        db_path (str): The path to the SQLite database file.
        data (List[Tuple[str, float]]): A list of tuples, where each tuple
                                         contains (title, price).

    Returns:
        bool: True if data was stored successfully, False otherwise.
    """
    if not data:
        logging.warning("No data provided to store.")
        return True # Not a failure, just nothing to do.

    # Rule #3: Ensure all input is validated.
    # Parameterized queries sanitize inputs, preventing SQL Injection.
    insert_query = "INSERT INTO books (title, price) VALUES (?, ?)"

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.executemany(insert_query, data)
            conn.commit()
        logging.info(f"Successfully stored {len(data)} items in the database.")
        return True
    except sqlite3.Error as e:
        logging.error(f"Failed to store data in database: {e}")
        return False

# --- Web Scraping Operations ---

def is_valid_url(url: str) -> bool:
    """
    Validates if the URL has a proper HTTP/HTTPS scheme.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    # Rule #3: Ensure all input is validated. This checks for a valid scheme.
    return url.lower().startswith(('http://', 'https effetti://'))

def fetch_html(url: str, timeout: int = 10) -> Optional[str]:
    """
    Fetches HTML content from a given URL.

    Args:
        url (str): The URL to fetch content from.
        timeout (int): Request timeout in seconds.

    Returns:
        Optional[str]: The HTML content as a string, or None if an error occurs.
    """
    if not is_valid_url(url):
        logging.error(f"Invalid URL scheme: {url}. Must be HTTP or HTTPS.")
        return None

    headers = {
        'User-Agent': 'My-Secure-Scraper/1.0 (Language=Python)'
    }

    try:
        # Rule #1 & #2: requests by default verifies SSL certs and hostnames.
        # We do not disable this (i.e., we don't use verify=False).
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)
        
        # Rule #5: Although not direct buffer control, checking content-type
        # helps avoid processing large, non-HTML files unexpectedly.
        if 'text/html' not in response.headers.get('Content-Type', ''):
             logging.warning(f"Content-Type is not text/html for URL: {url}")
             # We can still proceed, but it's good to be aware.
        
        return response.text
    # Rule #7: Catching specific exceptions for better error handling.
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL {url}: {e}")
        return None

def parse_book_data(html_content: str) -> List[Tuple[str, float]]:
    """
    Parses HTML content to extract book titles and prices.

    Args:
        html_content (str): The HTML content of the page.

    Returns:
        List[Tuple[str, float]]: A list of (title, price) tuples.
    """
    # Rule #6: Using BeautifulSoup for HTML parsing is safe against XXE.
    soup = BeautifulSoup(html_content, 'html.parser')
    books_data = []
    
    # The selector targets each book's container on books.toscrape.com
    articles = soup.find_all('article', class_='product_pod')

    for article in articles:
        # Using .get_text() and .strip() helps sanitize text content.
        title_tag = article.h3.a
        title = title_tag.get('title', '').strip() if title_tag else 'No Title'
        
        price_tag = article.find('p', class_='price_color')
        price_text = price_tag.get_text(strip=True) if price_tag else '£0.00'

        # Rule #3: Validate and sanitize extracted data.
        # Use regex to extract only the numeric part of the price.
        price_match = re.search(r'[\d\.]+', price_text)
        if title and price_match:
            try:
                price = float(price_match.group(0))
                books_data.append((title, price))
            except (ValueError, TypeError):
                logging.warning(f"Could not parse price for book: '{title}'")
    
    logging.info(f"Parsed {len(books_data)} book entries.")
    return books_data

# --- Main Orchestrator ---

def scrape_and_store(url: str, db_path: str) -> bool:
    """
    Orchestrates the scraping process: fetch, parse, and store.

    Args:
        url (str): The target URL to scrape.
        db_path (str): The path to the SQLite database.

    Returns:
        bool: True if the entire process was successful, False otherwise.
    """
    logging.info(f"Starting scrape for URL: {url}")

    if not setup_database(db_path):
        return False

    html_content = fetch_html(url)
    if not html_content:
        logging.error("Failed to fetch HTML content. Aborting.")
        return False
    
    parsed_data = parse_book_data(html_content)
    if not parsed_data:
        logging.warning("No data was parsed from the HTML content.")
        # This is not a failure of the process, so we can return True.
        return True

    if not store_data(db_path, parsed_data):
        logging.error("Failed to store parsed data. Aborting.")
        return False

    logging.info("Scraping and storing process completed successfully.")
    return True

# --- Verification and Main Execution ---

def read_from_db(db_path: str) -> List[Tuple]:
    """Reads all records from the 'books' table for verification."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT title, price FROM books")
            return cursor.fetchall()
    except sqlite3.Error as e:
        logging.error(f"Could not read from database: {e}")
        return []

def main():
    """Main function to run test cases."""
    db_file = "scraper_data.db"

    # Clean up previous database file before running tests
    if os.path.exists(db_file):
        os.remove(db_file)
        
    test_cases = [
        ("Test Case 1: Valid URL", "http://books.toscrape.com/", True),
        ("Test Case 2: 404 Not Found", "http://books.toscrape.com/not-a-real-page/", False),
        ("Test Case 3: Invalid domain", "http://this-domain-does-not-exist-abc123.com/", False),
        ("Test Case 4: Invalid URL scheme", "ftp://example.com", False),
        ("Test Case 5: URL with non-HTML content", "https://via.placeholder.com/150", True), # Should succeed but parse 0 items
    ]

    for i, (desc, url, expected_result) in enumerate(test_cases):
        print("\n" + "="*50)
        logging.info(f"Running {desc}")
        print("="*50)
        
        # For the first valid case, we want a fresh DB
        if i > 0 and os.path.exists(db_file):
            # For subsequent tests, we can keep the data or reset.
            # Let's reset for clarity.
            os.remove(db_file)

        success = scrape_and_store(url, db_file)

        if success:
            logging.info(f"Result for '{url}': SUCCESS (as expected: {expected_result})")
            scraped_data = read_from_db(db_file)
            logging.info(f"Found {len(scraped_data)} items in the database.")
            if scraped_data:
                # Print first 3 items for verification
                for item in scraped_data[:3]:
                    print(f"  - Title: {item[0]}, Price: {item[1]}")
        else:
            logging.error(f"Result for '{url}': FAILED (as expected: {expected_result})")
        
        assert success == expected_result, f"Test case '{desc}' failed!"

    # Clean up after all tests
    if os.path.exists(db_file):
        os.remove(db_file)
    print("\n" + "="*50)
    logging.info("All test cases passed.")
    print("="*50)


if __name__ == "__main__":
    # To run this script, you need to install the following libraries:
    # pip install requests beautifulsoup4
    main()