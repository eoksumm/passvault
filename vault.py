import sqlite3
from security import encrypt_vault_data, decrypt_vault_data

def add_password(user_id: int, master_password: str, salt: str, service_name: str, service_username: str, password_to_save: str):
    # Encrypt the password before saving it
    encrypted_password = encrypt_vault_data(master_password, salt, password_to_save)
    
    # Connect to database
    conn = sqlite3.connect('passvault.db')
    c = conn.cursor()
    
    # Save the vault item
    c.execute('''
        INSERT INTO vault (user_id, service_name, service_username, encrypted_password)
        VALUES (?, ?, ?, ?)
    ''', (user_id, service_name, service_username, encrypted_password))
    
    conn.commit()
    conn.close()

def get_passwords(user_id: int, master_password: str, salt: str):
    # Connect to database
    conn = sqlite3.connect('passvault.db')
    c = conn.cursor()
    
    # Get all saved passwords for this user
    c.execute('SELECT service_name, service_username, encrypted_password FROM vault WHERE user_id = ?', (user_id,))
    records = c.fetchall()
    conn.close()
    
    results = []
    for record in records:
        service_name_db, service_username_db, encrypted_password = record
        
        # Decrypt the password
        try:
            decrypted_password = decrypt_vault_data(master_password, salt, encrypted_password)
        except Exception:
            # If there is an error
            decrypted_password = "Error: Cannot decrypt"
            
        # Add to the list
        item = {
            "service": service_name_db,
            "username": service_username_db,
            "password": decrypted_password
        }
        results.append(item)
        
    return results
