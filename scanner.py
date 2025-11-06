import socket

target = "127.0.0.1"
port = 135

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)

result = sock.connect_ex((target, port))  # returns 0 if success, else error code

if result == 0:
    print(f"Port {port} is OPEN")
else:
    print(f"Port {port} is CLOSED")

sock.close()
