import sqlite3
import datetime

DB_FILE = "logs.db"

def initialize_db():
    """
    Create tables if they don't exist.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS firewall_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            action TEXT,
            rule_name TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS web_filter_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            action TEXT,
            filter_name TEXT,
            url TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username  TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

def add_login_event(username):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO login_events (timestamp, username)
        VALUES (?, ?)
    ''', (timestamp, username))
    conn.commit()
    conn.close()



def get_login_events():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, username FROM login_events ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "timestamp": ts,
            "description": f"User logged in: {user}"
        }
        for ts, user in rows
    ]


def add_log_entry(action, rule_name):
    """
    Add an entry to the firewall logs in the database.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO firewall_logs (timestamp, action, rule_name)
        VALUES (?, ?, ?)
    ''', (timestamp, action, rule_name))
    
    conn.commit()
    conn.close()

def get_logs():
    """
    Retrieve all firewall log entries from the database, including a 'description' field.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT timestamp, action, rule_name FROM firewall_logs")
    logs = cursor.fetchall()
    
    conn.close()
    return [
        {
            "timestamp": log[0],
            "description": f"{log[1]} firewall policy: {log[2]}"
        } for log in logs
    ]

def add_web_filter_log_entry(action, filter_name, url):
    """
    Add an entry to the web filter logs in the database.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO web_filter_logs (timestamp, action, filter_name, url)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, action, filter_name, url))
    
    conn.commit()
    conn.close()

def get_web_filter_logs():
    """
    Retrieve all web filter log entries from the database, including a 'description' field.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT timestamp, action, filter_name, url FROM web_filter_logs")
    logs = cursor.fetchall()
    
    conn.close()
    return [
        {
            "timestamp": log[0],
            "description": f"{log[1]} web filter: {log[2]} - URL: {log[3]}"
        } for log in logs
    ]


initialize_db()
