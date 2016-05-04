from hybrid import *
import socket

HOST = ''
PORT = 60085
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(5)
while 1:
    conn, addr = s.accept()
    data = conn.recv(4096)
    pri = RSA_load_key()
    d = hybrid_decrypt(data, pri)
    out = open("users.txt", "ab")
    out.write(d)
    out.close()
conn.close()
