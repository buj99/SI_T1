import socket
import sys
import _thread
import random
from Crypto.Cipher import AES
import secrets
encryption = []
key1 = secrets.token_bytes(16)
key2 = secrets.token_bytes(16)
key3 = "QfTjWnZr4u7x!z%C"
init_vector = "A1B2C3D4E5F6G7H8"
aes_send = AES.new(key3.encode(), AES.MODE_ECB)
aes_k1 = AES.new(key1, AES.MODE_ECB)
aes_k2 = AES.new(key2, AES.MODE_ECB)
connections_vector = []
port = 5001

def pad(input_bytes):
    padding_size = (16 - len(input_bytes)) % 16
    if padding_size == 0:
        padding_size = 16
    padding = (chr(padding_size) * padding_size).encode()
    return input_bytes+padding


def unpad(input_bytes):
    return input_bytes[:-ord(chr(input_bytes[-1]))]

def byte_xor(plaintext, encrypted_init_vector):
    return bytes([_a ^ _b for _a, _b in zip(plaintext, encrypted_init_vector)])

try:
    key_master = socket.socket()
    key_master.bind(('', port))
    key_master.listen(5)
    thread_index = 0
    global number_of_ok
    number_of_ok = 0

    def main(client, number_of_threads):
        global number_of_ok
        while True:
            received_data = client.recv(3).decode()
            if received_data == "ECB" or received_data == "CFB":
                encryption.append(received_data)
            print("Thread:", number_of_threads + 1, "User:", received_data)
            while len(encryption) % 2 and len(encryption) != 0:
                print("waiting")

            e1 = encryption[-1]
            e2 = encryption[-2]
            if e1 == e2:
                send_data = e1
            else:
                send_data = random.choice([e1, e2])

            if send_data == "ECB":
                encrypted_key1 = aes_send.encrypt(key1)
                client.send(b'0')
                client.send(encrypted_key1)

                ok = client.recv(16)
                print(aes_k1.decrypt(ok))
                if unpad(aes_k1.decrypt(ok)) == b'OK' and number_of_ok != 2:
                    number_of_ok += 1
                while number_of_ok != 2:
                    print("waiting oks")
                if number_of_ok == 2:
                    client.send(aes_k1.encrypt(pad(b'OK')))
                    encrypted_file_text = client.recv(16)
                    while encrypted_file_text:
                        connections_vector[1].send(encrypted_file_text)
                        encrypted_file_text = client.recv(16)
            else:
                encrypted_key2 = aes_send.encrypt(key2)
                encrypted_vector = aes_send.encrypt(init_vector.encode())
                client.send(b'1')
                client.send(encrypted_key2)
                client.send(encrypted_vector)

                ok = client.recv(16)
                print("Clienti", unpad(byte_xor(aes_k2.encrypt(init_vector.encode()), ok)))
                if unpad(byte_xor(aes_k2.encrypt(init_vector.encode()), ok)) == b'OK' and number_of_ok != 2:
                    number_of_ok += 1
                while number_of_ok != 2:
                    print("waiting oks")
                if number_of_ok == 2:
                    client.send(byte_xor(aes_k2.encrypt(init_vector.encode()), b'OK'))

                    encrypted_file_text = client.recv(16)
                    while encrypted_file_text:
                        connections_vector[1].send(encrypted_file_text)
                        encrypted_file_text = client.recv(16)


            if send_data == "OK":
                break
        client.close()

    while True:
        c, addr = key_master.accept()
        connections_vector.append(c)
        print("Socket Up and running with a connection from", addr)
        _thread.start_new_thread(main, (c, thread_index))
        thread_index += 1

except KeyboardInterrupt:
    print("\nClosing Connection and freeing the port.")
    c.close()
    sys.exit()

