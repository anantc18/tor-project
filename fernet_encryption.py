#!/bin/env python3
from cryptography.fernet import Fernet
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

'''
This method generates and returns the public and private keys.
'''


def generateKeys():
    m_length = 256*4
    private_key = RSA.generate(m_length, Random.new().read)
    public_key = private_key.publickey()
    return private_key, public_key


'''
This method uses the generated public key in generate_keys method
to encrypt data.
use private key to create new PKCS1_OAEP object for decryption
use that object to decrypry message
'''


def encrypt_message(data, publickey):
    encryptor_object = PKCS1_OAEP.new(publickey)
    encrypted_message = encryptor_object.encrypt(data)
    return encrypted_message


'''
This method uses the generated private key in generate_keys method
to decrypt data.
use private key to create new PKCS1_OAEP object for decryption
use that object to decrypry message
'''


def decrypt_message(encrypted_message, privatekey):
    decryptor_object = PKCS1_OAEP.new(privatekey)
    decrypted_message = decryptor_object.decrypt(encrypted_message)
    return decrypted_message


'''
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
'''

if __name__ == "__main__":
    # generate three public and private keys
    first_privatekey, first_publickey = generateKeys()
    second_privatekey, second_publickey = generateKeys()
    third_privatekey, third_publickey = generateKeys()

    # generate fernet keys
    first_fernet_key = Fernet.generate_key()
    second_fernet_key = Fernet.generate_key()
    third_fernet_key = Fernet.generate_key()


    # '''
    # ENCRYPTION
    # '''

    # # message to decrypt
    # MESSAGE = b"Hellow World"
    # print("Message to decrypt: ", MESSAGE)
    # print("")
    # # encrypt first message bytes with first fernet key
    # first_fernet = Fernet(first_fernet_key)
    # first_encrypted_bytes = first_fernet.encrypt(MESSAGE)
    # print("First Encrypted Message: ", first_encrypted_bytes)
    # # encrypt first fernet key
    # first_encrypted_msg_key = encrypt_message(
    #     first_fernet_key, first_publickey)
    # print("First Encrypted key: ", first_encrypted_msg_key)
    # print("")

    # # encrypt first_encrypted_bytes with second fernet key
    # second_fernet = Fernet(second_fernet_key)
    # second_encrypted_bytes = second_fernet.encrypt(first_encrypted_bytes)
    # print("Second Encrypted Message: ", second_encrypted_bytes)
    # # encrypt first fernet key
    # second_encrypted_msg_key = encrypt_message(
    #     second_fernet_key, second_publickey)
    # print("Second Encrypted key: ", second_encrypted_msg_key)
    # print("")

    # # encrypt second_encrypted_bytes with third fernet key
    # third_fernet = Fernet(third_fernet_key)
    # third_encrypted_bytes = third_fernet.encrypt(second_encrypted_bytes)
    # print("Third Encrypted Message: ", third_encrypted_bytes)
    # # encrypt third fernet key
    # third_encrypted_msg_key = encrypt_message(
    #     third_fernet_key, third_publickey)
    # print("Third Encrypted key: ", third_encrypted_msg_key)
    # print("")

    # '''
    # DECRYPTION
    # '''

    # print("Decryption process starting from third encrypted bytes to first encrypted bytes")
    # # Decrypt third_encrypted_msg_key for fernet to use to decrypt third_encrypted_bytes
    # third_decrypted_msg_key = decrypt_message(
    #     third_encrypted_msg_key, third_privatekey)
    # print("Third Decrypted key: ", third_decrypted_msg_key)
    # # use third_decrypted_msg_key to decrypt third_encrypted_bytes
    # third_decrypted_fernet = Fernet(third_decrypted_msg_key)
    # # decrypt third encrypted bytes
    # third_decrypted_bytes = third_decrypted_fernet.decrypt(
    #     third_encrypted_bytes)
    # print("Third Decrypted Message: ", third_decrypted_bytes)
    # print("")

    # # Decrypt second_decrypted_msg_key for fernet to use to decrypt second_encrypted_bytes
    # second_decrypted_msg_key = decrypt_message(
    #     second_encrypted_msg_key, second_privatekey)
    # print("Second Decrypted key: ", third_decrypted_msg_key)
    # # use second_decrypted_msg_key to decrypt second_encrypted_bytes
    # second_decrypted_fernet = Fernet(second_decrypted_msg_key)
    # # decrypt second encrypted bytes
    # second_decrypted_bytes = second_decrypted_fernet.decrypt(
    #     third_decrypted_bytes)
    # print("Second Decrypted Message: ", second_decrypted_bytes)
    # print("")

    # # Decrypt first_encrypted_msg_key for fernet to use to decrypt first_encrypted_bytes
    # first_decrypted_msg_key = decrypt_message(
    #     first_encrypted_msg_key, first_privatekey)
    # print("First Decrypted key: ", third_decrypted_msg_key)
    # # use first_decrypted_msg_key to decrypt first_encrypted_bytes
    # first_decrypted_fernet = Fernet(first_decrypted_msg_key)
    # # decrypt second encrypted bytes
    # first_decrypted_bytes = first_decrypted_fernet.decrypt(
    #     second_decrypted_bytes)
    # print("MESSAGE DECRYPTED:")
    # print(first_decrypted_bytes)
    # print("")

    # '''
    # NOTE: BELOW CODE NOT NEEDED. ONLY TO VERFIY PUBLIC/PRIVATE KEYS CAN BE REUSED FOR ENCRYPTIPON/DECRYPTION
    # '''

    # '''
    # ENCRYPTION
    # '''

    # # message to decrypt
    # MESSAGE = b"THIS IS AN ENCRYPTION MESSAGE"
    # print("Message to decrypt: ", MESSAGE)
    # print("")
    # # encrypt first message bytes with first fernet key
    # first_fernet = Fernet(first_fernet_key)
    # first_encrypted_bytes = first_fernet.encrypt(MESSAGE)
    # print("First Encrypted Message: ", first_encrypted_bytes)
    # # encrypt first fernet key
    # first_encrypted_msg_key = encrypt_message(
    #     first_fernet_key, first_publickey)
    # print("First Encrypted key: ", first_encrypted_msg_key)
    # print("")

    # # encrypt first_encrypted_bytes with second fernet key
    # second_fernet = Fernet(second_fernet_key)
    # second_encrypted_bytes = second_fernet.encrypt(first_encrypted_bytes)
    # print("Second Encrypted Message: ", second_encrypted_bytes)
    # # encrypt first fernet key
    # second_encrypted_msg_key = encrypt_message(
    #     second_fernet_key, second_publickey)
    # print("Second Encrypted key: ", second_encrypted_msg_key)
    # print("")

    # # encrypt second_encrypted_bytes with third fernet key
    # third_fernet = Fernet(third_fernet_key)
    # third_encrypted_bytes = third_fernet.encrypt(second_encrypted_bytes)
    # print("Third Encrypted Message: ", third_encrypted_bytes)
    # # encrypt third fernet key
    # third_encrypted_msg_key = encrypt_message(
    #     third_fernet_key, third_publickey)
    # print("Third Encrypted key: ", third_encrypted_msg_key)
    # print("")

    # '''
    # DECRYPTION
    # '''

    # print("Decryption process starting from third encrypted bytes to first encrypted bytes")
    # # Decrypt third_encrypted_msg_key for fernet to use to decrypt third_encrypted_bytes
    # third_decrypted_msg_key = decrypt_message(
    #     third_encrypted_msg_key, third_privatekey)
    # print("Third Decrypted key: ", third_decrypted_msg_key)
    # # use third_decrypted_msg_key to decrypt third_encrypted_bytes
    # third_decrypted_fernet = Fernet(third_decrypted_msg_key)
    # # decrypt third encrypted bytes
    # third_decrypted_bytes = third_decrypted_fernet.decrypt(
    #     third_encrypted_bytes)
    # print("Third Decrypted Message: ", third_decrypted_bytes)
    # print("")

    # # Decrypt second_decrypted_msg_key for fernet to use to decrypt second_encrypted_bytes
    # second_decrypted_msg_key = decrypt_message(
    #     second_encrypted_msg_key, second_privatekey)
    # print("Second Decrypted key: ", third_decrypted_msg_key)
    # # use second_decrypted_msg_key to decrypt second_encrypted_bytes
    # second_decrypted_fernet = Fernet(second_decrypted_msg_key)
    # # decrypt second encrypted bytes
    # second_decrypted_bytes = second_decrypted_fernet.decrypt(
    #     third_decrypted_bytes)
    # print("Second Decrypted Message: ", second_decrypted_bytes)
    # print("")

    # # Decrypt first_encrypted_msg_key for fernet to use to decrypt first_encrypted_bytes
    # first_decrypted_msg_key = decrypt_message(
    #     first_encrypted_msg_key, first_privatekey)
    # print("First Decrypted key: ", third_decrypted_msg_key)
    # # use first_decrypted_msg_key to decrypt first_encrypted_bytes
    # first_decrypted_fernet = Fernet(first_decrypted_msg_key)
    # # decrypt second encrypted bytes
    # first_decrypted_bytes = first_decrypted_fernet.decrypt(
    #     second_decrypted_bytes)
    # print("MESSAGE DECRYPTED:")
    # print(first_decrypted_bytes)
    # print("")

    # '''
    # ENCRYPTION
    # '''

    # # message to decrypt
    # MESSAGE = b"ANOTHER ENCRYPTION MESSAGE"
    # print("Message to decrypt: ", MESSAGE)
    # print("")
    # # encrypt first message bytes with first fernet key
    # first_fernet = Fernet(first_fernet_key)
    # first_encrypted_bytes = first_fernet.encrypt(MESSAGE)
    # print("First Encrypted Message: ", first_encrypted_bytes)
    # # encrypt first fernet key
    # first_encrypted_msg_key = encrypt_message(
    #     first_fernet_key, first_publickey)
    # print("First Encrypted key: ", first_encrypted_msg_key)
    # print("")

    # # encrypt first_encrypted_bytes with second fernet key
    # second_fernet = Fernet(second_fernet_key)
    # second_encrypted_bytes = second_fernet.encrypt(first_encrypted_bytes)
    # print("Second Encrypted Message: ", second_encrypted_bytes)
    # # encrypt first fernet key
    # second_encrypted_msg_key = encrypt_message(
    #     second_fernet_key, second_publickey)
    # print("Second Encrypted key: ", second_encrypted_msg_key)
    # print("")

    # # encrypt second_encrypted_bytes with third fernet key
    # third_fernet = Fernet(third_fernet_key)
    # third_encrypted_bytes = third_fernet.encrypt(second_encrypted_bytes)
    # print("Third Encrypted Message: ", third_encrypted_bytes)
    # # encrypt third fernet key
    # third_encrypted_msg_key = encrypt_message(
    #     third_fernet_key, third_publickey)
    # print("Third Encrypted key: ", third_encrypted_msg_key)
    # print("")

    # '''
    # DECRYPTION
    # '''

    # print("Decryption process starting from third encrypted bytes to first encrypted bytes")
    # # Decrypt third_encrypted_msg_key for fernet to use to decrypt third_encrypted_bytes
    # third_decrypted_msg_key = decrypt_message(
    #     third_encrypted_msg_key, third_privatekey)
    # print("Third Decrypted key: ", third_decrypted_msg_key)
    # # use third_decrypted_msg_key to decrypt third_encrypted_bytes
    # third_decrypted_fernet = Fernet(third_decrypted_msg_key)
    # # decrypt third encrypted bytes
    # third_decrypted_bytes = third_decrypted_fernet.decrypt(
    #     third_encrypted_bytes)
    # print("Third Decrypted Message: ", third_decrypted_bytes)
    # print("")

    # # Decrypt second_decrypted_msg_key for fernet to use to decrypt second_encrypted_bytes
    # second_decrypted_msg_key = decrypt_message(
    #     second_encrypted_msg_key, second_privatekey)
    # print("Second Decrypted key: ", third_decrypted_msg_key)
    # # use second_decrypted_msg_key to decrypt second_encrypted_bytes
    # second_decrypted_fernet = Fernet(second_decrypted_msg_key)
    # # decrypt second encrypted bytes
    # second_decrypted_bytes = second_decrypted_fernet.decrypt(
    #     third_decrypted_bytes)
    # print("Second Decrypted Message: ", second_decrypted_bytes)
    # print("")

    # # Decrypt first_encrypted_msg_key for fernet to use to decrypt first_encrypted_bytes
    # first_decrypted_msg_key = decrypt_message(
    #     first_encrypted_msg_key, first_privatekey)
    # print("First Decrypted key: ", third_decrypted_msg_key)
    # # use first_decrypted_msg_key to decrypt first_encrypted_bytes
    # first_decrypted_fernet = Fernet(first_decrypted_msg_key)
    # # decrypt second encrypted bytes
    # first_decrypted_bytes = first_decrypted_fernet.decrypt(
    #     second_decrypted_bytes)
    # print("MESSAGE DECRYPTED:")
    # print(first_decrypted_bytes)
    # print("")
