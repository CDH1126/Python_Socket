import tkinter
import socket
from threading import Thread
from nacl.public import PrivateKey, PublicKey, Box

def send(event=None):
    msg = input_msg.get()
    enc_msg = box.encrypt(msg.encode("utf-8"))
    sock.send(enc_msg)
    input_msg.set("")

    if msg == "end":
        sock.close()
        win.quit()

def recvMessage():
    try:
        while True:
            enc_msg = sock.recv(1024)
            try:
                decoded = box.decrypt(enc_msg).decode("utf-8")
            except Exception:
                continue

            if decoded.startswith("[USERLIST]"):
                userlist_str = decoded[len("[USERLIST] "):]
                userlist = userlist_str.split(",")
                win.after(0, update_user_list, userlist)
            else:
                win.after(0, chat_list.insert, tkinter.END, decoded)
    except ConnectionAbortedError:
        print("서버로부터 연결이 강제로 종료됨")

def on_delete(event=None):
    input_msg.set("end")
    send()

def update_user_list(userlist):
    whisper_menu.delete(0, tkinter.END)
    for user in userlist:
        if user:
            whisper_menu.add_command(label=user, command=lambda u=user: insert_whisper_command(u))

def insert_whisper_command(username):
    current = input_msg.get()
    input_msg.set(f"/w {username} " + current)

# GUI 구성
win = tkinter.Tk()
win.title("채팅 프로그램")

frame = tkinter.Frame(win)
input_msg = tkinter.StringVar()

scroll = tkinter.Scrollbar(frame)
scroll.pack(side=tkinter.RIGHT, fill=tkinter.Y)

chat_list = tkinter.Listbox(frame, height=15, width=50, yscrollcommand=scroll.set)
chat_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
frame.pack()

inputbox = tkinter.Entry(win, textvariable=input_msg)
inputbox.bind("<Return>", send)
inputbox.pack(side=tkinter.LEFT, fill=tkinter.BOTH, expand=tkinter.YES, padx=5, pady=5)

send_button = tkinter.Button(win, text="전송", command=send)
send_button.pack(side=tkinter.RIGHT, fill=tkinter.X, padx=5, pady=5)

whisper_button = tkinter.Menubutton(win, text="귓속말", relief=tkinter.RAISED)
whisper_menu = tkinter.Menu(whisper_button, tearoff=0)
whisper_button.config(menu=whisper_menu)
whisper_button.pack(side=tkinter.LEFT, padx=5)

win.protocol("WM_DELETE_WINDOW", on_delete)

# 서버 연결
IP = "localhost"
PORT = 9999
print(f"접속: {IP}:{PORT}")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((IP, PORT))

# 키 쌍 생성 및 교환
client_private_key = PrivateKey.generate()
client_public_key = client_private_key.public_key

server_public_key_bytes = sock.recv(32)
server_public_key = PublicKey(server_public_key_bytes)

sock.send(client_public_key.encode())

box = Box(client_private_key, server_public_key)

receive_thread = Thread(target=recvMessage)
receive_thread.start()

win.mainloop()
