# Instructions for running this Python code:
# 1. You need to install three external libraries: requests, beautifulsoup4, and lxml.
# 2. You can install them using pip:
#    pip install requests
#    pip install beautifulsoup4
#    pip install lxml
# 3. Once the libraries are installed, you can run the script directly:
#    python your_script_name.py

import sqlite3
import requests
from bs4 import BeautifulSoup
from typing import List, Tuple

def setup_database(db_name: str):
    """Creates the database and the 'books' table if they don't exist."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            price TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def scrape_data(url: str) -> List[Tuple[str, str]]:
    """Scrapes book titles and prices from a given URL."""
    books = []
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        soup = BeautifulSoup(response.content, 'lxml')
        articles = soup.find_all('article', class_='product_pod')
        for article in articles:
            title_tag = article.h3.a
            title = title_tag['title'] if title_tag else 'No Title'
            price_tag = article.find('p', class_='price_color')
            price = price_tag.get_text(strip=True) if price_tag else 'No Price'
            books.append((title, price))
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
    return books

def store_data(db_name: str, books: List[Tuple[str, str]]):
    """Stores a list of books into the database."""
    if not books:
        return
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.executemany('INSERT INTO books (title, price) VALUES (?, ?)', books)
    conn.commit()
    conn.close()

def print_data(db_name: str):
    """Prints all records from the 'books' table."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    print(f"\n--- Data in {db_name} ---")
    try:
        cursor.execute('SELECT id, title, price FROM books')
        rows = cursor.fetchall()
        if not rows:
            print("No data found in the 'books' table.")
        else:
            for row in rows:
                print(f"ID: {row[0]}\tTitle: {row[1]}\tPrice: {row[2]}")
    except sqlite3.Error as e:
        print(f"Error reading from database: {e}")
    finally:
        print("--------------------------")
        conn.close()

def clear_table(db_name: str):
    """Deletes all records from the 'books' table."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM books')
    conn.commit()
    conn.close()
    print("\nTable 'books' cleared.")


if __name__ == "__main__":
    DB_NAME = "scraper_db.sqlite"
    URL1 = "http://books.toscrape.com/"
    URL2 = "http://books.toscrape.com/catalogue/page-2.html"

    setup_database(DB_NAME)

    # Test Case 1: Scrape data from the first URL
    print(f"--- Test Case 1: Scraping {URL1} ---")
    books1 = scrape_data(URL1)
    store_data(DB_NAME, books1)
    print(f"Scraped and stored {len(books1)} books.")

    # Test Case 2: Print the stored data
    print("\n--- Test Case 2: Printing data ---")
    print_data(DB_NAME)

    # Test Case 3: Clear the database table
    print("\n--- Test Case 3: Clearing table ---")
    clear_table(DB_NAME)

    # Test Case 4: Print the data again to confirm it's empty
    print("\n--- Test Case 4: Printing empty table ---")
    print_data(DB_NAME)

    # Test Case 5: Scrape data from the second URL and print it
    print(f"\n--- Test Case 5: Scraping {URL2} and printing ---")
    books2 = scrape_data(URL2)
    store_data(DB_NAME, books2)
    print(f"Scraped and stored {len(books2)} books.")
    print_data(DB_NAME)