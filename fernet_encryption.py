#!/bin/env python3
from cryptography.fernet import Fernet

# first encrypt
first_key = Fernet.generate_key()  
first_fernet = Fernet(first_key)
first_encrypted_bytes = first_fernet.encrypt(b"Hellow World")
print(first_encrypted_bytes)
print("")

# second encrypt
second_key = Fernet.generate_key()  
second_fernet = Fernet(second_key)
second_encrypted_bytes = second_fernet.encrypt(first_encrypted_bytes)
print(second_encrypted_bytes)
print("")

# third encrypt
third_key = Fernet.generate_key()  
third_fernet = Fernet(third_key)
third_encrypted_bytes = third_fernet.encrypt(second_encrypted_bytes)
print(third_encrypted_bytes)
print("")

# Decrypt
third_decrypted_bytes = third_fernet.decrypt(third_encrypted_bytes)
print(third_decrypted_bytes)
print("")
second_decrypted_bytes = second_fernet.decrypt(third_decrypted_bytes)
print(second_decrypted_bytes)
print("")
first_decrypted_bytes = first_fernet.decrypt(second_decrypted_bytes)
print(first_decrypted_bytes)