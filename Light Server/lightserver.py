#Nathan Sexton

import socket
import threading
import sys
import struct
ENCODING = 'utf-8' 

#specify server ip, port, and logfile in case no input is given
IP_ADDR = '127.0.0.1'
PORT = 8001
logfile = 'logfile'

#receive command line arguments
for args in sys.argv:
    if args == '-s':
        IP_ADDR = sys.argv[sys.argv.index(args)+1]
    if args == '-p':
        PORT = int(sys.argv[sys.argv.index(args)+1])
    if args == '-l':
        logfile = sys.argv[sys.argv.index(args)+1]
   


#pack vars into struct
def packing(fversion, fmsgType, fmsgLength, fmsg):
    return struct.pack(f'! 3i {fmsgLength}s', fversion, fmsgType, fmsgLength, fmsg.encode())


def handle_client(conn, addr):
    print("Handling connection from {}".format(addr))
    while conn:        
        #receiving data
        byte_received = conn.recv(struct.calcsize('! 3i 5s'))
        version, msgType, msgLength, msg = struct.unpack('! 3i 5s', byte_received)
        print("Data Received:: Version:", version, " Message Type:", msgType, " Length:", msgLength, " Msg:", msg)

        #writing to file and sending output 
        if version == 17:
            File_object.write("VERSION ACCEPTED")
            print("VERSION ACCEPTED")

        else:
            File_object.write("VERSION MISMATCH")
            print("VERSION MISMATCH")
            print("Server will continue to listen on {}".format(addr))
            break


        #send hello to client
        serverMsg = 'HELLO'
        serverMsgLength = len(serverMsg)
        serverVersion = 17
        serverMsgType = 1


        #packing
        serverPacket = packing(serverVersion, serverMsgType, serverMsgLength, serverMsg)

        #sending
        conn.sendall(serverPacket)

        #receiving and unpacking
        while True:

            byte_received2 = connection.recv(struct.calcsize('! 3i 7s'))
            version2, msgType2, msgLength2, msg2 = struct.unpack('! 3i 7s', byte_received2)
            print("Command Message Received")

            #writing to file and sending output
            if version2 == 17:
                print("VERSION ACCEPTED")

                if msgType2 == 1:
                    File_object.write(f"EXECUTING SUPPORTED COMMAND: LIGHTON")
                    print(f"EXECUTING SUPPORTED COMMAND: LIGHTON")

                elif msgType2 == 2:
                    File_object.write(f"EXECUTING SUPPORTED COMMAND: LIGHTOFF")
                    print(f"EXECUTING SUPPORTED COMMAND: LIGHTOFF")

                else:
                    File_object.write(f"IGNORING UNKNOWN COMMAND: {msg2}")
                    print(f"IGNORING UNKNOWN COMMAND: {msg2}")
            else:
                File_object.write("VERSION MISMATCH")
                print("VERSION MISMATCH")


        #sending success to client
            print("Returning SUCCESS to Client")
            serverMsg2 = 'SUCCESS'
            serverMsgLength2 = len(serverMsg2)
            serverVerison2 = 17
            serverMsgType2 = 1

        #packing
            serverPacket2 = packing(serverVerison2, serverMsgType2, serverMsgLength2, serverMsg2)

        #sending
            connection.sendall(serverPacket2)
            break
        break

          





if __name__ == '__main__':
    #create a TCP socket
    print("Creating a socket")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  
    SERVER_ADDR = (IP_ADDR, PORT)
    print("Binding to {}".format(SERVER_ADDR))
    server_socket.bind(SERVER_ADDR)
    

    #listening
    server_socket.listen()
    print("Server is listening on {}".format(SERVER_ADDR))


    while True:
        connection, address = server_socket.accept()
        print("Received a connection from {}".format(address))

        #writing to file
        File_object = open(logfile, "w")
        File_object.write(f"Received connection from {connection}".format(connection))

        thread = threading.Thread(target=handle_client, args=(connection, address))
        thread.start()


        
    

    

