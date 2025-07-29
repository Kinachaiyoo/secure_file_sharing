import sqlite3
import os

# Ensure the database directory exists
os.makedirs("database", exist_ok=True)

# Connect to SQLite database
conn = sqlite3.connect("database/app.db")
cursor = conn.cursor()

# Create users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    position TEXT NOT NULL,
    password TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    comment TEXT DEFAULT '',
    login_token TEXT DEFAULT ''
)
""")

# Create documents table
cursor.execute("""
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_name TEXT NOT NULL,
    signed_by TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    comment TEXT DEFAULT ''
)
""")

# Create shared_files table
cursor.execute("""
CREATE TABLE IF NOT EXISTS shared_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    filename TEXT NOT NULL,
    password TEXT,
    encrypted_path TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# ✅ Create chat_logs table (used by app.py)
cursor.execute("""
CREATE TABLE IF NOT EXISTS chat_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# ✅ Add receiver column if missing
try:
    cursor.execute("ALTER TABLE shared_files ADD COLUMN receiver TEXT")
    print("✅ Added missing column: receiver")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e):
        print("ℹ️ 'receiver' column already exists — skipping.")
    else:
        raise

conn.commit()
conn.close()
print("✅ Database initialized successfully with all tables.")
