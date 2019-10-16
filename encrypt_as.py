import socket
import time
# from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


PORT = 8080
host = 'localhost'


def generate_key_pair():
    key = RSA.generate(2048)
    with open('rsa_key.pub', 'wb') as f:
        f.write(key.publickey().export_key())
    with open('rsa_key.priv', 'wb') as f:
        f.write(key.export_key())


def get_key(key_type):
    return RSA.importKey(open('rsa_key.{}'.format(key_type)).read())


def get_message():
    return "test".encode('utf-8')
    # return input("Type message which you want to send").encode('utf-8')


def as_encryption(key, message):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)


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


if __name__ == "__main__":
    connection = create_connection()
    key = get_key('pub')
    message = get_message()
    data = as_encryption(key, message)
    send_data(data, connection)
    # generate_key_pair()






