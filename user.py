import sqlite3
from security import hash_master_password, verify_master_password, generate_encryption_salt

def register_user(username: str, master_password: str) -> bool:
    # Hash the password and make a salt
    password_hash = hash_master_password(master_password)
    encryption_salt = generate_encryption_salt()
    
    # Connect to the database
    conn = sqlite3.connect('passvault.db')
    c = conn.cursor()
    
    try:
        # Save user to database
        c.execute('''
            INSERT INTO users (username, password_hash, encryption_salt)
            VALUES (?, ?, ?)
        ''', (username, password_hash, encryption_salt))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # This happens if username is already taken
        return False
    finally:
        conn.close()

def login_user(username: str, master_password: str):
    # Connect to the database
    conn = sqlite3.connect('passvault.db')
    c = conn.cursor()
    
    # Find the user by username
    c.execute('SELECT id, password_hash, encryption_salt FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    # Check if user exists
    if user is None:
        return None
        
    user_id, password_hash, encryption_salt = user
    
    # Check if password matches
    if verify_master_password(master_password, password_hash):
        # Return user details to use later
        return {"id": user_id, "salt": encryption_salt}
    else:
        return None
