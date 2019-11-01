from Crypto.Random import get_random_bytes
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
import os
import socket
import time

PORT = 8080
host = 'localhost'


#Generujemy klucz symetryczny z losowego ciagu bajtow
def get_randomBytes(length):
    key = get_random_bytes(length)
    print("Your key: ",key)

    return key


def encode_mode_CBC(generated_key,filename):
    output_file = 'encrypted_file.bin'
    filename_bytes = filename.encode("utf-8")

    #Zamieniamy plik na bajty
    in_file = open(filename, "rb")
    data = in_file.read()
    in_file.close()

    #Szyfrujemy plik
    cipher = AES.new(generated_key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(data, AES.block_size))
    ciphered_filename = cipher.encrypt(pad(filename_bytes, AES.block_size))

    #Zapisujemy plik poniewaz musimy dodac jeszcze IV na poczatek
    file_out = open(output_file, "wb")
    file_out.write(cipher.iv)
    file_out.write(ciphered_data)
    file_out.close()

    #Wczytujemy calosc a plik usuwamy
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

    #Zapisujemy plik poniewaz musimy dodac jeszcze IV na poczatek
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


def encode_mode_EAX(generated_key,filename):

    # filename_bytes = filename.encode("utf-8")
    # # Zamieniamy plik na bajty
    # in_file = open(filename, "rb")
    # data = in_file.read()
    # in_file.close()
    # cipher = AES.new(generated_key, AES.MODE_EAX)
    # ciphertext, tag = cipher.encrypt_and_digest(data)
    #
    # file_out = open("encrypted.bin", "wb")
    # [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]


    output_file = 'encrypted_file.bin'
    filename_bytes = filename.encode("utf-8")
    tag=0
    # Zamieniamy plik na bajty
    in_file = open(filename, "rb")
    data = in_file.read()
    in_file.close()
    print(type(data),type(filename_bytes))
    # Szyfrujemy plik
    cipher = AES.new(generated_key, AES.MODE_EAX)
    print(cipher)
    ciphered_data, tag = cipher.encrypt_and_digest(data)
    ciphered_filename = cipher.encrypt_and_digest(filename_bytes)

    # Zapisujemy plik poniewaz musimy dodac jeszcze nonce i tag na poczatek
    file_out = open(output_file, "wb")
    file_out.write(cipher.nonce)
    file_out.write(tag)
    file_out.write(ciphered_data)
    file_out.close()

    # Wczytujemy calosc a plik usuwamy
    encrypted_file = open(output_file, "rb")
    encrypted_data = encrypted_file.read()
    encrypted_file.close()
    os.remove(output_file)

    return encrypted_data, ciphered_filename


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


def send_data(function, cipher_mode):
    connection_with_server = connect_to_server()
    start_time = time.time()
    print("Connected to server, sending cipher mode...")
    connection_with_server.send(cipher_mode.encode())
    print("Cipher mode was sent, waiting for server public key...")
    server_public_key = connection_with_server.recv(2048)
    print("Got public key from server: {}. Sending random bytes to server encrypted with his public key...".format(
        server_public_key))
    # #TODO: Te pliku musimy w takiej kolejnosci przeslac do serwera
    # #szyfrujemy kluczem aasymetrycznym klucz AES
    encoded_key = encode_RSA_key(bytes, server_public_key)

    connection_with_server.send(encoded_key)
    print("Encrypted symetric key was sent to server, sending filename")

    # # Szyfrujemy plik oraz IV i jego nazwe:
    cbc_data, cbc_filename = function(bytes, file_name)
    # print(cbc_data)
    # print(cbc_filename)
    print("Sending filename...")
    connection_with_server.send(cbc_filename)

    print(connection_with_server.recv(15).decode())
    print("Sending data...")
    connection_with_server.send(cbc_data)
    print(connection_with_server.recv(20).decode())
    print("Execution time for {} was {}".format(cipher_mode, start_time - time.time()))
    connection_with_server.shutdown(1)

if __name__ == "__main__":

    print("SFTP client V 0.1")

    # TODO: informacje o połączeniu itd, dopiero potem ten wybór kluczy (tak myśle, że spoko bedzie)


    print("Type filename to send:")
    file_name = 'test.jpg'
    # file_name = input()



    #Wybór długości klucza AES
    print("Choose your symmetric cipher by typing 1, 2 or 3:")
    print("1.AES-128 \n2.AES-192  \n3.AES-256")

    key_option = input()
    key_bool,option_bool = True,True
    bytes = None
    while key_bool is True:
        if key_option == str(1):
            bytes = get_randomBytes(16)
            print(len(bytes))
            key_bool = False
        elif key_option == str(2):
            bytes  = get_randomBytes(24)
            key_bool = False
        elif key_option == str(3):
            bytes  = get_randomBytes(32)
            key_bool = False
        else:
            print("Choose proper number.")
            key_option = input()

    # Wybór szyfrogramu
    print("Choose mode for symmetric cipher:")
    print("1.CBC \n2.CFB  \n3.EAX \n4.RSA")

    cipher_mode = input()
    while option_bool is True:
        if cipher_mode == str(1):

            send_data(encode_mode_CBC, 'CBC')

            option_bool = False

        elif  cipher_mode == str(2):
            # #TODO: Te pliku musimy w takiej kolejnosci przeslac do serwera
            #
            # # szyfrujemy kluczem symetrycznym info o rodzaju moda
            # encoded_mode = encode_RSA_mode('CFB')
            #
            # # szyfrujemy kluczem asymetrycznym klucz AES
            # encoded_key = encode_RSA_key(bytes)
            #
            # # Szyfrujemy plik oraz IV i jego nazwe:
            # cfb_data, cfb_filename = encode_mode_CFB(bytes, file_name)
            # print(cfb_data)
            # print(cfb_filename)
            send_data(encode_mode_CFB, 'CFB')
            option_bool = False

        elif  cipher_mode == str(3):
            # # TODO: Te pliku musimy w takiej kolejnosci przeslac do serwera
            #
            # # szyfrujemy kluczem symetrycznym info o rodzaju moda
            # encoded_mode = encode_RSA_mode('EAX')
            #
            # # szyfrujemy kluczem asymetrycznym klucz AES
            # encoded_key = encode_RSA_key(bytes)
            #
            # # Szyfrujemy plik oraz IV i jego nazwe:
            #
            # eax_data, eax_filename = encode_mode_EAX(bytes, file_name)
            # print(eax_data)
            # print(eax_filename)
            send_data(encode_mode_EAX, 'EAX')
            option_bool = False
        elif cipher_mode == str(4):
            connection_with_server = connect_to_server()
            start_time = time.time()
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
            print(connection_with_server.recv(20).decode())
            print("Execution time for {} was {}".format(cipher_mode, start_time - time.time()))
            connection_with_server.shutdown(1)
            option_bool = False
        else:
            # cipher_mode = input()
            print("Choose proper number.")


    sys.exit()