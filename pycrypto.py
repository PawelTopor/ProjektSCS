import sys
import socket
from _thread import start_new_thread
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

PORT = 8080
HOST = ''
salt = b'k\x93nYL\x8a^\xcb\x04\xfe\x8aE\x07\xff\xc6\x92I\x08\xa4\xbe\xe9\x1c\xa7\x9f\xb2\xe3\rs}\x88\x02\xec'
# print(get_random_bytes(32))

def generateKey():
    password = input("Please type encryption password")
    key = PBKDF2(password, salt, dkLen=32)
    return key

def CBC_decryption(key, message):
    print(message)
    iv = message[0:16]
    print(iv)
    data = message[16:]
    print(data)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(data)

def wait_for_connection():

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as msg:
        print("Could not create socket. Error Code: ", str(msg[0]), "Error: ", msg[1])
        sys.exit(0)

    print("[-] Socket Created")


    try:
        s.bind((HOST, PORT))
        print("[-] Socket Bound to port " + str(PORT))
    except socket.error as msg:
        print("Bind Failed. Error Code: {} Error: {}".format(str(msg[0]), msg[1]))
        sys.exit()

    s.listen(10)
    print("Listening...")


    # def client_thread(conn, addr):
    #     if not players_list:
    #         players_list.append(addr[0])
    #         conn.sendall(b'server')
    #     else:
    #         ip = players_list[-1]
    #         players_list.pop()
    #         conn.sendall(bytes(ip, 'utf-8'))
    #     conn.close()

    conn, addr = s.accept()
    print("[-] Connected to " + addr[0] + ":" + str(addr[1]))
    data = conn.recv(1024)
    return conn, data
    # start_new_thread(client_thread, (conn, addr))


if __name__== "__main__":
    connection, message = wait_for_connection()
    key = generateKey()
    print(CBC_decryption(key, message))