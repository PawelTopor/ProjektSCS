import socket
import time
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
# import pycryptodome
from Crypto.Random import get_random_bytes


PORT = 8080
host = 'localhost'
salt = b'k\x93nYL\x8a^\xcb\x04\xfe\x8aE\x07\xff\xc6\x92I\x08\xa4\xbe\xe9\x1c\xa7\x9f\xb2\xe3\rs}\x88\x02\xec'
# print(get_random_bytes(32))

def generateKey():
    # password = input("Please type encryption password")
    password = "test"
    key = PBKDF2(password, salt, dkLen=32)
    return key

def get_message():
    return "test"
    # return input("Type message which you want to send")

def CBC_encryption(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(message, AES.block_size))
    print(cipher.iv)
    print(cipher.iv + ciphered_data)
    return cipher.iv + ciphered_data

def send_data(data, connection):
    connection.sendall(data)



def create_connection():
    s = socket.socket()
    while True:
        try:
            s.connect((host, PORT))
            return s
        except ConnectionRefusedError:
            time.sleep(2)
            print("Server niedostepny...Czekaj")



if __name__== "__main__":
    connection = create_connection()
    key = generateKey()
    message = get_message().encode()
    data = CBC_encryption(key, message)
    send_data(data, connection)





