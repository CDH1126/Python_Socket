import socketserver
from nacl.public import PrivateKey, PublicKey, Box
import nacl.utils

class MyHandler(socketserver.BaseRequestHandler):
    # 유저 관리
    users = {}  # username: (conn, addr, client_public_key, box)

    # 서버의 키 쌍 생성
    server_private_key = PrivateKey.generate()
    server_public_key = server_private_key.public_key

    def unicast(self, from_user, to_user, msg):
        if to_user not in self.users:
            sender_conn, _, _, _ = self.users[from_user]
            sender_conn.send(self.users[from_user][3].encrypt(f"[서버] {to_user}가 없습니다.\n".encode()))
            return

        sender_conn, _, _, sender_box = self.users[from_user]
        receiver_conn, _, _, receiver_box = self.users[to_user]

        # 받는 사람에게 보낼 메시지
        receiver_conn.send(receiver_box.encrypt(f"[{from_user}]의 귓속말 : {msg}\n".encode()))

        # 보내는 사람에게 보낼 메시지
        sender_conn.send(sender_box.encrypt(f"[{to_user}]에게 보냄 : {msg}\n".encode()))

    def broadcast_userlist(self):
        userlist_msg = "[USERLIST] " + ",".join(self.users.keys())
        for conn, _, _, box in self.users.values():
            conn.send(box.encrypt(userlist_msg.encode()))

    def broadcast(self, msg):
        for conn, _, _, box in self.users.values():
            conn.send(box.encrypt(msg.encode()))

    def addUser(self, username, conn, addr, client_public_key):
        if username in self.users:
            temp_box = Box(self.server_private_key, client_public_key)
            conn.send(temp_box.encrypt("이미 등록되어 있습니다\n".encode()))
            return None

        box = Box(self.server_private_key, client_public_key)
        self.users[username] = (conn, addr, client_public_key, box)
        self.broadcast(f"{username}이 참석했습니다\n")
        print(f"채팅 참여 인원 {len(self.users)}")
        self.broadcast_userlist()
        return username

    def delUser(self, username):
        del self.users[username]
        self.broadcast(f"{username}이 퇴장했습니다")
        print(f"채팅 참여 인원 {len(self.users)}")
        self.broadcast_userlist()

    def handle(self):
        print(self.client_address[0])

        # 클라이언트와 공개키 교환
        self.request.send(self.server_public_key.encode())
        client_public_key_bytes = self.request.recv(32)
        client_public_key = PublicKey(client_public_key_bytes)
        box = Box(self.server_private_key, client_public_key)

        while True:
            self.request.send(box.encrypt('이름을 입력하세요 \n입력: '.encode()))
            enc_username = self.request.recv(1024)
            try:
                username = box.decrypt(enc_username).decode()
            except Exception:
                continue
            if self.addUser(username, self.request, self.client_address, client_public_key):
                break

        while True:
            try:
                enc_data = self.request.recv(1024)
                message = box.decrypt(enc_data).decode()
            except Exception:
                continue

            print(f"[{username}] : {message}")

            if message == "end":
                self.request.close()
                break

            if message.startswith("/w "):
                try:
                    _, to_user, whisper_msg = message.split(' ', 2)
                    if to_user == username:
                        self.request.send(box.encrypt("자신에게는 보낼 수 없습니다\n".encode()))
                        continue
                    self.unicast(username, to_user, whisper_msg)
                except ValueError:
                    self.request.send(box.encrypt("귓속말 형식: /w 유저이름 내용\n".encode()))
                continue

            self.broadcast(f"[{username}] : {message}")

        print(f"[{username}] 접속종료")
        self.delUser(username)

class ChatServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

print("chat server start..")

chat_serv = ChatServer(('', 9999), MyHandler)
chat_serv.serve_forever()
chat_serv.shutdown()
chat_serv.server_close()
