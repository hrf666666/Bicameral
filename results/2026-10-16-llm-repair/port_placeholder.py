import socket
# 案例A注入：python 裸 socket 占住 18011 —— accept 但永不应答（health 只能超时）
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 18011))
s.listen(64)
conns = []
while True:
    try:
        c, _ = s.accept()
        conns.append(c)
    except OSError:
        break
