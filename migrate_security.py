"""
migrate_security.py
-------------------
Run this ONCE to upgrade an existing IntelGraph database with the new
security columns added in the hardened app.py.

Usage:
    python3 migrate_security.py

Safe to run multiple times — it skips columns that already exist.
"""
import sqlite3
import os

DB_PATH = os.path.join('instance', 'intelgraph.db')

def run():
    if not os.path.exists(DB_PATH):
        print(f'[-] Database not found at {DB_PATH}')
        print('[*] If this is a fresh install, just run the app — it will create the DB automatically.')
        return

    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    migrations = [
        # (table, column_name, column_definition)
        ('user', 'failed_logins',  'INTEGER DEFAULT 0'),
        ('user', 'last_login_ip',  'VARCHAR(45)'),
        ('user', 'created_at',     "DATETIME DEFAULT '2024-01-01 00:00:00'"),
        ('user', 'locked_until',   'DATETIME'),          # timed cooldown expiry
    ]

    for table, col, defn in migrations:
        try:
            c.execute(f'ALTER TABLE {table} ADD COLUMN {col} {defn}')
            print(f'[+] Added column: {table}.{col}')
        except sqlite3.OperationalError as e:
            if 'duplicate column' in str(e).lower():
                print(f'[~] Already exists: {table}.{col}  (skipped)')
            else:
                print(f'[!] Error on {table}.{col}: {e}')

    # Reset failed_logins to 0 for all existing users (safe default)
    c.execute('UPDATE user SET failed_logins = 0 WHERE failed_logins IS NULL')
    conn.commit()
    conn.close()
    print('\n[✓] Migration complete.')

if __name__ == '__main__':
    run()
