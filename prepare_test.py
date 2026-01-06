import os
import json
import base64
import hashlib
from cryptography.fernet import Fernet

GRADES_FILE = 'grades_encrypted.json'
UIS_PASSWORD_ENV = 'UISPsw'

def get_encryption_key(password):
    """Generates a Fernet key from the UIS password (same logic as crawler)."""
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode('utf-8')).digest())
    return key

def main():
    uis_password = os.environ.get(UIS_PASSWORD_ENV)
    
    if not os.path.exists(GRADES_FILE):
        print(f"Error: '{GRADES_FILE}' not found. Please run the main 'crawl_grades.py' script once to generate it.")
        return

    if not uis_password:
        print(f"Error: '{UIS_PASSWORD_ENV}' environment variable not set.")
        return

    key = get_encryption_key(uis_password)
    f = Fernet(key)

    print(f'[*] Reading and decrypting {GRADES_FILE}...')
    with open(GRADES_FILE, 'rb') as file:
        encrypted_data = file.read()

    try:
        decrypted_data = json.loads(f.decrypt(encrypted_data))
    except Exception as e:
        print(f"[-] Decryption failed. The password in '{UIS_PASSWORD_ENV}' might be incorrect. Error: {e}")
        return

    print('[*] Modifying grades data for test...')
    semesters = decrypted_data['semesterId2studentGrades']
    if not semesters:
        print("  - No semesters found in the data. Cannot modify.")
        return
        
    first_semester_id = list(semesters.keys())[0]
    if semesters[first_semester_id]:
        removed_course = semesters[first_semester_id].pop(0)
        print(f'  - Removed course: {removed_course["courseName"]}')
    else:
        print('  - No courses to remove in the first semester.')

    print(f'[*] Re-encrypting and saving to {GRADES_FILE}...')
    new_encrypted_data = f.encrypt(json.dumps(decrypted_data, ensure_ascii=False).encode('utf-8'))
    with open(GRADES_FILE, 'wb') as file:
        file.write(new_encrypted_data)

    print('[+] Test data prepared. The encrypted file now contains one less course.')

if __name__ == '__main__':
    main()