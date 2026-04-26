"""
reset_failed_logins.py
----------------------
Run this ONCE to clear the failed_logins counter and locked_until values
that built up during testing. Safe to run any time.

Usage:
    python3 reset_failed_logins.py
"""
import sqlite3, os

DB_PATH = os.path.join('instance', 'intelgraph.db')

if not os.path.exists(DB_PATH):
    print(f'[-] Database not found at {DB_PATH}')
else:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Also add locked_until column if it doesn't exist yet
    try:
        c.execute('ALTER TABLE user ADD COLUMN locked_until DATETIME')
        print('[+] Added locked_until column')
    except sqlite3.OperationalError:
        print('[~] locked_until column already exists')

    # Reset all counters and clear all cooldowns
    c.execute('UPDATE user SET failed_logins = 0, locked_until = NULL, is_locked = 0 WHERE id != 1')
    # Super admin: just reset counter, never lock
    c.execute('UPDATE user SET failed_logins = 0, locked_until = NULL WHERE id = 1')

    rows = conn.total_changes
    conn.commit()
    conn.close()
    print(f'[✓] Reset failed_logins and cleared all cooldowns for {rows} users.')
    print('[✓] Done — you can now log in normally.')
