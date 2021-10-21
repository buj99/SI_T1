import socket
import sys
from Crypto.Cipher import AES

key1 = ""
key2 = ""
key3 = "QfTjWnZr4u7x!z%C"
aes_k3 = AES.new(key3.encode(), AES.MODE_ECB)
# aes_cfb = AES.new(key2.encode(), AES.MODE_ECB)
number_of_blocks_sent = 0
KM_PORT=5001
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
    s = socket.socket()
    s.connect(('127.0.0.1', KM_PORT))
    while True:
        message = input()
        s.send(message.encode())

        flag = s.recv(1)

        if flag == b'0':
            key1 = s.recv(16)
            key1 = aes_k3.decrypt(key1)

            aes_k1 = AES.new(key1, AES.MODE_ECB)
            s.send(aes_k1.encrypt(pad(b'OK')))
            if unpad(aes_k1.decrypt(s.recv(16))) == b'OK':
                file = open("UserA.txt", "rb")
                byte = file.read(16)
                while byte:

                    if len(byte) < 16:
                        s.send(aes_k1.encrypt(pad(byte)))
                    else:
                        s.send(aes_k1.encrypt(byte))
                    byte = file.read(16)
        else:
            key2 = s.recv(16)
            init_vector = s.recv(16)

            key2 = aes_k3.decrypt(key2)
            init_vector = aes_k3.decrypt(init_vector)

            aes_k2 = AES.new(key2, AES.MODE_ECB)

            s.send(byte_xor(aes_k2.encrypt(init_vector), pad(b'OK')))

            ok = s.recv(16)
            print(ok)
            print(byte_xor(aes_k2.encrypt(init_vector), ok))

            if byte_xor(aes_k2.encrypt(init_vector), ok) == b'OK':
                file = open("inputA.txt", "rb")
                byte = file.read(16)
                while byte:

                    init_vector = aes_k2.encrypt(init_vector)
                    if len(byte) < 16:
                        s.send(byte_xor(init_vector, pad(byte)))
                    else:
                        s.send(byte_xor(init_vector, byte))
                    byte = file.read(16)

    s.close()

except KeyboardInterrupt:
    print("Closing Connection and freeing the port.")
    s.close()
    sys.exit()