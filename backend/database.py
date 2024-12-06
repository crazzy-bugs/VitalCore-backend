import sqlite3
from contextlib import contextmanager

DATABASE = 'antivirus.db'

# Initialize the database and ensure tables are created
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        
        # Table for scans
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                location TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                result TEXT DEFAULT NULL,
                final_result TEXT DEFAULT NULL,
                scan_logs TEXT DEFAULT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            )
        ''')

        # Table for notifications
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            )
        ''')

        # Table for antiviruses
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS av (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                av_name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                av_exec_command TEXT,
                av_update_command TEXT,
                custom_field TEXT
            )
        ''')

        conn.commit()


# Context manager for database connection
@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Allows rows to be returned as dictionaries
    try:
        yield conn
    finally:
        conn.close()
