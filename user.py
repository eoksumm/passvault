import sqlite3
from security import hash_master_password, verify_master_password, generate_encryption_salt


def register_user(username: str, master_password: str) -> bool:
    password_hash = hash_master_password(master_password)
    encryption_salt = generate_encryption_salt()
    conn = sqlite3.connect('passvault.db')
    c = conn.cursor()
    try:
        c.execute(
            'INSERT INTO users (username, password_hash, encryption_salt) VALUES (?, ?, ?)',
            (username, password_hash, encryption_salt)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def login_user(username: str, master_password: str):
    conn = sqlite3.connect('passvault.db')
    c = conn.cursor()
    c.execute('SELECT id, password_hash, encryption_salt FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user is None:
        return None

    user_id, password_hash, encryption_salt = user
    if verify_master_password(master_password, password_hash):
        return {'id': user_id, 'salt': encryption_salt}
    return None
