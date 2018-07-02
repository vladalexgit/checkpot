import socket

host = '127.0.0.1'
port = 22

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
banner = s.recv(1024)
s.send('\n\n\n\n\n\n\n\n')
response = s.recv(1024)
print(response)  # "bad packet length" is twisted, Protocol mismatch. is correct
s.close()

if "168430090" in response:
    print('[!] Kippo honeypot detected!')
