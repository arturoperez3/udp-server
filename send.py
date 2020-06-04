import pickle
import socket
import time
import random


random.seed(0x1337)


with open('payload_dump.bin', 'rb') as f:
    payloads = pickle.load(f, encoding="bytes")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
count = 0

for payload in payloads:
    count += 1
    sock.sendto(payload, ('127.0.0.1', 1337))
    time.sleep(0.001)

# p = []
# for payload in payloads: 
#     p.append(payload)

# random.shuffle(p)
    

# for payload in p:
#     sock.sendto(payload, ('127.0.0.1', 1337))
#     time.sleep(0.001)

print (count)

sock.close()