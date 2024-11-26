import requests
from cryptography.fernet import Fernet
import json

SERVER_URL = 'https://vodlex.lol'
KEY = 'ywe2mhynqqV3wGGZku6JO3wD7YSRyDg_J_2K6Ao5rn8='
CIPHER_SUITE = Fernet(KEY)

def decrypt_data(encrypted_data):
    decrypted_data = CIPHER_SUITE.decrypt(encrypted_data.encode('latin1'))
    return json.loads(decrypted_data.decode())

def authenticate(username, password, hwid):
    response = requests.get(f'{SERVER_URL}/get_users')
    if response.status_code != 200:
        return False

    encrypted_users = response.content.split(b'\n')
    
    for encrypted_user in encrypted_users:
        if not encrypted_user:
            continue
        try:
            decrypted_user = decrypt_data(encrypted_user.decode('latin1'))
            if decrypted_user['username'] == username and decrypted_user['password'] == password and decrypted_user['hwid'] == hwid:
                return True
        except Exception as e:
            print(e)
    return False