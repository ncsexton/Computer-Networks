#Nathan Sexton

import socket
import struct
import sys
ENCODING = 'utf-8'

#define vars in case of no command line input
REMOTE_ADDR = '127.0.0.1'
REMOTE_PORT = 8001
logfile = 'logfile'

#get command line arguments
for args in sys.argv:
    if args == '-s':
        REMOTE_ADDR = sys.argv[sys.argv.index(args)+1]
    elif args == '-p':
        REMOTE_PORT = int(sys.argv[sys.argv.index(args)+1])
    elif args == '-l':
       logfile = sys.argv[sys.argv.index(args)+1]

#server object
SERVER_ADDR = (REMOTE_ADDR, REMOTE_PORT)
#socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#connecting client to server
client.connect(SERVER_ADDR)

print("Received connection from: {}".format(SERVER_ADDR))

#message vars
msg = 'HELLO'
msgLength = len(msg)
version = 17
msgType = 1

#method for packing vars
def packing(fversion, fmsgType, fmsgLength, fmsg):
    return struct.pack(f'! 3i {fmsgLength}s', fversion, fmsgType, fmsgLength, fmsg.encode())

#packing
packed = packing(version, msgType, msgLength, msg)

print("Sending HELLO Packet")
#sending the packet
client.send(packed)

#receiving the server's reciprocated "hello message"
serverReceived = client.recv(struct.calcsize('! 3i 5s'))
sversion, smsgType, smsgLength, smsg = struct.unpack('! 3i 5s', serverReceived)
print("Data Received. Version: ", sversion, " Message Type: ", smsgType, " Message Length: ", smsgLength)

File_object = open(logfile, "w")

if sversion == 17:
    print("VERSION ACCEPTED")
    File_object.write("VERSION ACCEPTED")
    print("Hello Message Received")

    #command message vars
    msg2 = "LIGHTON"
    msgLength2 = len(msg2)
    version2 = 17
    msgType2 = 1

    #packing
    packed2 = packing(version2, msgType2, msgLength2, msg2)

    #sending command packet
    print("Sending Command")
    client.sendall(packed2)

    #receiving success message
    serverReceived2 = client.recv(struct.calcsize('! 3i 7s'))
    sversion2, smsgType2, smsgLength2, smsg2 = struct.unpack('! 3i 7s', serverReceived2)
    File_object.write(f"Server response: {smsg2}")
    print("Command Successful")
    print("Closing Socket")
    client.close()


else:
    print("VERSION MISMATCH")
    File_object.write("VERSION MISMATCH")

    print("Closing Socket")
    client.close()

