import sqlite3

# Define the database file
db_file = "ads.db"

# Define the text file containing the URLs
text_file = "ads.txt"  # Change this to your actual file name

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

# Create table if not exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS porn_urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE NOT NULL
    )
''')

# Read URLs from the text file
with open(text_file, "r", encoding="utf-8") as file:
    urls = [line.strip() for line in file if line.strip()]  # Remove empty lines and whitespace

# Insert URLs into the database
for url in urls:
    try:
        cursor.execute("INSERT INTO porn_urls (url) VALUES (?)", (url,))
    except sqlite3.IntegrityError:
        print(f"Duplicate URL skipped: {url}")  # Avoid duplicate URLs

# Commit and close connection
conn.commit()
conn.close()

print(f"Successfully inserted {len(urls)} URLs into the database.")
