import sqlite3
from security import encrypt_vault_data, decrypt_vault_data


def add_password(user_id: int, master_password: str, salt: str, service_name: str, service_username: str, password_to_save: str):
    encrypted_password = encrypt_vault_data(master_password, salt, password_to_save)
    conn = sqlite3.connect('passvault.db')
    c = conn.cursor()
    c.execute(
        'INSERT INTO vault (user_id, service_name, service_username, encrypted_password) VALUES (?, ?, ?, ?)',
        (user_id, service_name, service_username, encrypted_password)
    )
    conn.commit()
    conn.close()


def get_passwords(user_id: int, master_password: str, salt: str):
    conn = sqlite3.connect('passvault.db')
    c = conn.cursor()
    c.execute(
        'SELECT id, service_name, service_username, encrypted_password FROM vault WHERE user_id = ?',
        (user_id,)
    )
    records = c.fetchall()
    conn.close()

    results = []
    for entry_id, service_name, service_username, encrypted_password in records:
        try:
            decrypted_password = decrypt_vault_data(master_password, salt, encrypted_password)
        except Exception:
            decrypted_password = '[decryption error]'
        results.append({
            'id': entry_id,
            'service': service_name,
            'username': service_username,
            'password': decrypted_password,
        })
    return results


def delete_password(user_id: int, entry_id: int):
    conn = sqlite3.connect('passvault.db')
    c = conn.cursor()
    # user_id check ensures users can only delete their own entries
    c.execute('DELETE FROM vault WHERE id = ? AND user_id = ?', (entry_id, user_id))
    conn.commit()
    conn.close()
