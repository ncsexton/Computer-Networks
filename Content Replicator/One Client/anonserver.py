#Nathan Sexton, April 2021

import socket
import struct
import sys
import urllib.request, urllib.error, urllib.parse
import time
import logging
import os

#Function to pack the packets that will be sent
def packThePacket(sNum, aNum, ack, syn, fin):
    packer = struct.Struct('>iii')
    lastLine = ack*2*2 + syn*2 + fin
    packet = packer.pack(sNum, aNum, lastLine)
    return packet


#Parses the packages that are being unpacked
def msgParser(msg):
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


#Function to create the logfile
def packetLog(sNum, aNum, ack, syn, fin, logType):
	
	#Converts from binary to string
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
		logging.info(f"RECV {sNum} {aNum} {ACK} {SEQ} {FIN}\n")
	elif logType == 1:
		logging.info(f"SEND {sNum} {aNum} {ACK} {SEQ} {FIN}\n")
	elif logType == 2:
		logging.info(f"RETRAN {sNum} {aNum} {ACK} {SEQ} {FIN}\n")

		
#Gets the content of the specified url	
def URLDownload(url):
    url = 'http://' + url
    with urllib.request.urlopen(url) as f:
        html = f.read()
        h = open('url.html', 'wb')
        h.write(html)
        h.close()
    return html
	
#Returns the specified payload number for the given file
def fileParser(myFile, payloadNumber):
	
	if len(myFile) < (512*payloadNumber)-1:
		finished = True
		theDifference = (payloadNumber*512) - len(myFile)
		return myFile[(payloadNumber-1)*512 : len(myFile)]+bytes("0"*theDifference, 'utf-8'), finished
	else:
		finished = False
	
	#Returns the payload portion
	return myFile[(payloadNumber-1)*512 : ((payloadNumber*512)-1)], finished

#Stop and wait function
def stopAndWait(mySocket, buffSiz, myHeader, myPayload, portNum, seqNumber, ackNumber, ack, syn, fin):
    servMsg = 0
    mySocket.settimeout(300)
    
    #Can get rid of exponential backoff
    while not servMsg:
        servMsg = mySocket.recvfrom(buffSiz)
        
        if not servMsg:
            #Resends the packet
            mySocket.sendto(myHeader, portNum)
            mySocket.sendto(myPayload, portNum)
            #Logs that a retransmit was made
            logType = 2
            packetLog(seqNumber, ackNumber, ack, syn, fin, logType)
        time.sleep(.5)
    return servMsg

#Function to update the sequence and ack numbers
def numberUpdater(seqNumber, ackNumber):
    newAckNumber = seqNumber + 1
    
    if ackNumber == 0:
        newSeqNumber = 100
    else:
        newSeqNumber = ackNumber
    return newSeqNumber, newAckNumber


##########################################################################################################
#Beginning of main code
##########################################################################################################

#Grabbing command line arguments
for args in sys.argv:
    if args == '-p':
        localPort = int(sys.argv[sys.argv.index(args)+1])
    if args == '-l':
        logfile = sys.argv[sys.argv.index(args)+1]
    if args == '-w':
        url = sys.argv[sys.argv.index(args)+1]

logging.basicConfig(filename=(os.getcwd() + '/' + logfile), level=logging.INFO)
doneSending = False
counter = 1

#Variable that holds the downloaded webpage
downloadedHTML = URLDownload(url)
#Opening socket and binding IP
localIP = socket.gethostbyname(socket.gethostname())
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind((localIP, localPort))

# Listen for incoming datagrams
listen = 1
while(listen == 1):
    try:
        print("UDP server up and listening")
        #First packet headers
        recvInfo, addr = UDPServerSocket.recvfrom(96)
        seqNumberR, ackNumberR, ackr, synr, finr = msgParser(recvInfo)
        packetLog(seqNumberR, ackNumberR, ackr, synr, finr, 0)
        seqNumberR, ackNumberR = numberUpdater(seqNumberR, ackNumberR)
        ackr = 1
        packetLog(seqNumberR, ackNumberR, ackr, synr, finr, 1)
        handshakePack = packThePacket(seqNumberR, ackNumberR, ackr, synr, finr)
        #Sends ack back
        UDPServerSocket.sendto(handshakePack, addr)

        #Completing the handshake
        recvInfo, addr = UDPServerSocket.recvfrom(96)
        seqNumberR, ackNumberR, ackr, synr, finr = msgParser(recvInfo)
        packetLog(seqNumberR, ackNumberR, ackr, synr, finr, 0)
        synr = 0
        tempVar = ackNumberR
        ackNumberR = seqNumberR + 1
        seqNumberR = tempVar
        print("Handshake Complete")
		

        while(doneSending == False):
			
            currentPayload, doneSending = fileParser(downloadedHTML, counter)
			
            if doneSending == 1:
                finr = 1
            
            seqNumberR, ackNumberR = numberUpdater(seqNumberR, ackNumberR)
            newHeader = packThePacket(seqNumberR, ackNumberR, ackr, synr, finr)
            UDPServerSocket.sendto(newHeader, addr)
            packetLog(seqNumberR, ackNumberR, ackr, synr, finr, 1)
            UDPServerSocket.sendto(currentPayload, addr)
            print("Sent payload number: ", counter)
			
            counter = counter + 1
            header = stopAndWait(UDPServerSocket, 96, newHeader, currentPayload, localPort, seqNumberR, ackNumberR, ackr, synr, finr)
            seqNumberR, ackNumberR, ackr, synr, finr = msgParser(header[0])

        doneSending = False
        fin = 0
        counter = 1
        print("Final payload transfer complete")
        #Message for keyboard interupt
    except KeyboardInterrupt:
        print("Exiting now...")
        UDPServerSocket.close()
        break
