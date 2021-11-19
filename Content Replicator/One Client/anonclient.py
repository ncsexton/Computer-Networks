#Nathan Sexton, April 2021

import socket
import sys
import struct
import random
import logging
import time

#Function to pack the packet that will be sent
def packThePacket(sNum, aNum, ack, syn, fin):
	packer = struct.Struct('>iii')
	lastLine = ack*2*2 + syn*2 + fin
	packet = packer.pack(sNum, aNum, lastLine)
	return packet

#Stop and wait function
def stopAndWait(mySocket, buffSiz, myPacket, portNum, seqNumber, ackNumber, ack, syn, fin, File_object):
	servMsg = 0
	mySocket.settimeout(1)
	
	while not servMsg:
		try:
			servMsg = mySocket.recvfrom(buffSiz)
		except ConnectionResetError:
			print("Not a port number of the valid server")
			exit(0)
		if not servMsg:
			#Resends the packet
			UDPClientSocket.sendto(firstPacket, serverAddressPort)
			#Logs that a retransmit was made
			logType = 2
			packetLog(seqNumber, ackNumber, ack, syn, fin, File_object, logType)
			print("Seq: ", seqNumber, "Ack: ", ackNumber)
		time.sleep(.5)
	return servMsg

#Parses the received packets flag bits
def msgParser(msg):

	if len(msg) > 12:
		print("Packet lost, goodbye")
		exit()

	unpackedMsg = struct.unpack('>iii', msg)
	seqNumber = unpackedMsg[0]
	ackNumber = unpackedMsg[1]
	flags = unpackedMsg[2]
	
	#Determines which flags are set based on the value of the flags variable
	if flags >= 4:
		ack = 1
		flags = flags - 4
	else:
		ack = 0
	if flags >= 2:
		syn = 1
		flags = flags - 2
	else:
		syn = 0
	if flags >= 1:
		fin = 1
	else:
		fin = 0
	
	return seqNumber, ackNumber, ack, syn, fin
	
#Function for creating the logfile
def packetLog(sNum, aNum, ack, syn, fin, File_object, logType):
	
	#Converts from binary to string for logging purposes
	if ack == 1:
		ACK = "ACK"
	else:
		ACK = ""
	
	if ack == 1:
		SEQ = "SEQ"
	else:
		SEQ = ""
	
	if fin == 1:
		FIN = "FIN"
	else:
		FIN = ""
	
	if logType == 0:
		File_object.write(f"RECV {sNum} {aNum} {ACK} {SEQ} {FIN}\n")
	elif logType == 1:
		File_object.write(f"SEND {sNum} {aNum} {ACK} {SEQ} {FIN}\n")
	elif logType == 2:
		File_object.write(f"RETRAN {sNum} {aNum} {ACK} {SEQ} {FIN}\n")

#Function to update the sequence and ack numbers
def numberUpdater(seqNumber, ackNumber):
	newAckNumber = seqNumber + 512

	newSeqNumber = ackNumber
	return newSeqNumber, newAckNumber

##########################################################################################################
#Beginning of main code
##########################################################################################################

#grabbing command line arguments
for args in sys.argv:
    if args == '-s':
        server = sys.argv[sys.argv.index(args)+1]
    elif args == '-p':
        port = int(sys.argv[sys.argv.index(args)+1])
    elif args == '-l':
        logfile = sys.argv[sys.argv.index(args)+1]
		
File_object = open(logfile, "w")
msgFromClient       = "Hello UDP Server"
bytesToSend         = str.encode(msgFromClient)
serverAddressPort   = (server, port)
bufferSize          = 96
#Number of failed attempts to send/recieve data from server
numFails = 0
#Sets sequence number to 32 bits
seqNumber = 12345
#Sets ACK number to 32 bits
ackNumber = 0
#Set default for flags
ack = 0
syn = 1
fin = 0
firstPacket = packThePacket(seqNumber, ackNumber, ack, syn, fin)

# Create a UDP socket at client side
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
#Handshake start
# Send to server using created UDP socket
UDPClientSocket.sendto(firstPacket, serverAddressPort)
logType = 0
#log to file
packetLog(seqNumber, ackNumber, ack, syn, fin, File_object, logType)
#Response from the server
msg = stopAndWait(UDPClientSocket, bufferSize, firstPacket, serverAddressPort, seqNumber, ackNumber, ack, syn, fin, File_object)
#Parse the response
seqNumber, ackNumber, ack, syn, fin = msgParser(msg[0])
logtype = 1
packetLog(seqNumber, ackNumber, ack, syn, fin, File_object, logType)
print("Handshake complete")

#Create response packet
myPacket = packThePacket(seqNumber, ackNumber, ack, syn, fin)
#Second half of handshake
UDPClientSocket.sendto(myPacket, serverAddressPort)
#Payload loop
while(not fin):
	#Get response from the server
	seqNumber = 1000000
	while seqNumber > 999999:
		header = stopAndWait(UDPClientSocket, bufferSize, myPacket, serverAddressPort, seqNumber, ackNumber, ack, syn, fin, File_object)
		seqNumber, ackNumber, ack, syn, fin = msgParser(header[0])
	payload = UDPClientSocket.recvfrom(512)

	packetLog(seqNumber, ackNumber, ack, syn, fin, File_object, 0)

	#Send seq and ack based on values brought in
	seqNumber, ackNumber = numberUpdater(seqNumber, ackNumber)
	packetLog(seqNumber, ackNumber, ack, syn, fin, File_object, 1)
	print("Seq number: ", seqNumber,"\n", "Ack number: ", ackNumber)

	myPacket = packThePacket(seqNumber, ackNumber, ack, syn, fin)
	UDPClientSocket.sendto(myPacket, serverAddressPort)

print("Payload transfer complete")
UDPClientSocket.close()
