import sys
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

PORT = 8080
HOST = ''


def get_key(key_type):
    return RSA.importKey(open('rsa_key.{}'.format(key_type)).read())


def generate_key_pair():
    key = RSA.generate(2048)
    with open('rsa_key.pub', 'wb') as f:
        f.write(key.publickey().export_key())
    with open('rsa_key.priv', 'wb') as f:
        f.write(key.export_key())


def as_decryption(key, message):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(message).decode('utf-8')


def wait_for_connection():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error:
        print("Could not create socket")
        sys.exit(0)

    print("[-] Socket Created")
    try:
        s.bind((HOST, PORT))
        print("[-] Socket Bound to port " + str(PORT))
    except socket.error:
        print("Bind Failed")
        sys.exit()

    s.listen(1)
    print("Listening...")

    conn, addr = s.accept()
    print("[-] Connected to " + addr[0] + ":" + str(addr[1]))
    data = conn.recv(1024)
    return conn, data


if __name__ == "__main__":
    connection, message = wait_for_connection()
    key = get_key("priv")
    print("Got message:", as_decryption(key, message))
