import sys
import socket
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

PORT = 8080
HOST = ''
salt = b'k\x93nYL\x8a^\xcb\x04\xfe\x8aE\x07\xff\xc6\x92I\x08\xa4\xbe\xe9\x1c\xa7\x9f\xb2\xe3\rs}\x88\x02\xec'
# print(get_random_bytes(32))


def generate_key():
    password = "test"
    # password = input("Please type encryption password")
    key = PBKDF2(password, salt, dkLen=32)
    return key


def cbc_decryption(key, message):
    iv = message[0:16]
    data = message[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(data), AES.block_size).decode('utf-8')


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

    s.listen(10)
    print("Listening...")

    conn, addr = s.accept()
    print("[-] Connected to " + addr[0] + ":" + str(addr[1]))
    data = conn.recv(1024)
    return conn, data


if __name__ == "__main__":
    connection, message = wait_for_connection()
    key = generate_key()
    print("Got message:", cbc_decryption(key, message))
