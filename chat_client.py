import socket
from threading import Thread
from nacl.public import PrivateKey, PublicKey, Box

def recvData(sock, box):
    try:
        while True:
            enc_data = sock.recv(1024)
            try:
                data = box.decrypt(enc_data).decode()
                print(data, end='')
            except Exception:
                continue
    except ConnectionAbortedError:
        print('서버로부터 연결이 강제 종료됨')

# 1. 소켓 생성
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# 2. 접속 시도
sock.connect(("127.0.0.1", 9999))

# 키 쌍 생성 및 교환
client_private_key = PrivateKey.generate()
client_public_key = client_private_key.public_key

server_public_key_bytes = sock.recv(32)
server_public_key = PublicKey(server_public_key_bytes)

sock.send(client_public_key.encode())

box = Box(client_private_key, server_public_key)

th = Thread(target=recvData, args=(sock, box))
th.daemon = True
th.start()

while True:
    send_data = input()
    enc_data = box.encrypt(send_data.encode())
    sock.send(enc_data)

    if send_data == "end":
        break

sock.close()
print("클라이언트 종료")
