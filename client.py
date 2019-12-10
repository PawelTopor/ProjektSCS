from Crypto.Random import get_random_bytes
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
# from Crypto.Util.Padding import unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import socket
import time

PORT = 8080
host = 'localhost'


# Generujemy klucz symetryczny z losowego ciagu bajtow
def get_randomBytes(length):
    key = get_random_bytes(length)
    print("Your key: ",key)

    return key


def encode_mode_CBC(generated_key,filename):
    output_file = 'encrypted_file.bin'
    filename_bytes = filename.encode("utf-8")

    # Zamieniamy plik na bajty
    in_file = open(filename, "rb")
    data = in_file.read()
    in_file.close()

    # Szyfrujemy plik
    cipher = AES.new(generated_key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(data, AES.block_size))
    ciphered_filename = cipher.encrypt(pad(filename_bytes, AES.block_size))

    # Zapisujemy plik poniewaz musimy dodac jeszcze IV na poczatek
    file_out = open(output_file, "wb")
    file_out.write(cipher.iv)
    file_out.write(ciphered_data)
    file_out.close()

    # Wczytujemy calosc a plik usuwamy
    encrypted_file = open(output_file, "rb")
    encrypted_data = encrypted_file.read()
    encrypted_file.close()
    os.remove(output_file)

    return encrypted_data,ciphered_filename


def encode_mode_CFB(generated_key,filename):
    output_file = 'encrypted_file.bin'
    filename_bytes = filename.encode("utf-8").strip()

    # Zamieniamy plik na bajty
    in_file = open(filename, "rb")
    data = in_file.read()
    in_file.close()

    # Szyfrujemy plik
    cipher = AES.new(generated_key, AES.MODE_CFB)
    ciphered_data = cipher.encrypt(data)
    ciphered_filename = cipher.encrypt(filename_bytes)

    # Zapisujemy plik poniewaz musimy dodac jeszcze IV na poczatek
    file_out = open(output_file, "wb")
    file_out.write(cipher.iv)
    file_out.write(ciphered_data)
    file_out.close()

    # Wczytujemy calosc a plik usuwamy
    encrypted_file = open(output_file, "rb")
    encrypted_data = encrypted_file.read()
    encrypted_file.close()
    os.remove(output_file)

    return encrypted_data,ciphered_filename


# Szyfrujemy klucz symetryczny
def encode_RSA_key(bytes, server_public_key):
    pu_key = RSA.import_key(server_public_key)
    # pu_key = RSA.import_key(open('server_RSA_pubic.pem', 'r').read())
    cipher = PKCS1_OAEP.new(key=pu_key)
    cipher_text = cipher.encrypt(bytes)

    return cipher_text


# Szyfrujemy nazwe wybranego moda
def encode_RSA_mode(mode_type, server_public_key):
    mode_bytes = str.encode(mode_type)
    pu_key = RSA.import_key(server_public_key)
    # pu_key = RSA.import_key(open('server_RSA_pubic.pem', 'r').read())
    cipher = PKCS1_OAEP.new(key=pu_key)
    cipher_text = cipher.encrypt(mode_bytes)

    return cipher_text


def connect_to_server():
    s = socket.socket()
    while True:
        try:
            s.connect((host, PORT))
            return s
        except ConnectionRefusedError:
            time.sleep(2)
            print("Server niedostepny...Czekaj")


def send_data(function, cipher_mode, aes_bytes):
    connection_with_server = connect_to_server()
    start_time = time.time()
    print("Connected to server, sending cipher mode...")
    connection_with_server.send(cipher_mode.encode())
    print("Cipher mode was sent, waiting for server public key...")
    server_public_key = connection_with_server.recv(2048)
    print("Got public key from server: {}. Sending random bytes to server encrypted with his public key...".format(
        server_public_key))
    #szyfrujemy kluczem aasymetrycznym klucz AES
    encoded_key = encode_RSA_key(aes_bytes, server_public_key)

    connection_with_server.send(encoded_key)
    print("Encrypted symetric key was sent to server, sending filename")

    # Szyfrujemy plik oraz IV i jego nazwe:
    cbc_data, cbc_filename = function(aes_bytes, file_name)
    print("Sending filename...")
    connection_with_server.send(cbc_filename)

    print(connection_with_server.recv(15).decode())
    print("Sending data...")
    connection_with_server.send(cbc_data)
    connection_with_server.shutdown(1)
    print("Execution time for {} was {}".format(cipher_mode,  time.time() - start_time))

def choose_aes_length():
    # Wybór długości klucza AES
    print("Choose your symmetric cipher by typing 1, 2 or 3:")
    print("1.AES-128 \n2.AES-192  \n3.AES-256")

    key_option = input()
    while True:
        if key_option == str(1):
            return get_randomBytes(16)
        elif key_option == str(2):
            return get_randomBytes(24)
        elif key_option == str(3):
            return get_randomBytes(32)
        else:
            print("Choose proper number.")
            key_option = input()


if __name__ == "__main__":
    option_bool = True
    print("SFTP client V 0.1")


    print("Type filename to send:")
    # file_name = 'movie.mp4'
    file_name = input()



    # Wybór szyfrogramu
    print("Choose mode for symmetric cipher:")
    print("1.CBC \n2.CFB \n3.RSA")

    cipher_mode = input()
    while option_bool is True:
        if cipher_mode == str(1):
            aes_bytes = choose_aes_length()
            send_data(encode_mode_CBC, 'CBC', aes_bytes)
            option_bool = False

        elif  cipher_mode == str(2):
            aes_bytes = choose_aes_length()
            send_data(encode_mode_CFB, 'CFB', aes_bytes)
            option_bool = False
        elif cipher_mode == str(3):
            connection_with_server = connect_to_server()
            print("Connected to server, sending cipher mode...")
            connection_with_server.send(b'RSA')
            print("Cipher mode was sent, waiting for server public key...")
            server_public_key = connection_with_server.recv(2048)
            max_bytes_len = 214 if len(server_public_key) == 450 else 86
            print("Got public key from server: {}. Sending filename..".format(server_public_key))
            connection_with_server.send(encode_RSA_mode(file_name, server_public_key))
            print(connection_with_server.recv(20).decode())
            print("Sending data...")
            with open(file_name, 'rb') as file:
                data = file.read(max_bytes_len)
                while data:
                    connection_with_server.send(encode_RSA_key(data, server_public_key))
                    data = file.read(max_bytes_len)
            connection_with_server.shutdown(1)
            option_bool = False
        else:
            print("Choose proper number.")
            cipher_mode = input()

    sys.exit()
