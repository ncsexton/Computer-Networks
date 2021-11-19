import socket
import struct
import argparse
import logging
import sys
import random


#Function called for client to handshake the Loadbalancer, then receive the Loadbalancer's
#choice, then taking the received choice (the replicaserver's IP) and contacting the chosen server
def meet_loadbalancer(client_socket, server_addr):
    #send initial sequence number
    client_seq = random.randint(0,4294967295) #0 to 2^32 -1, as in TCP
    print("Client Sequence Number:", client_seq)
    server_seq = 0

    #send first handshake packet
    #syn + ISN
    send_packet(client_socket, server_addr, client_seq, server_seq, '010')
    #receive SYN+ACK, SET REMOTE
    #seq_num, ack_num, flags  = recv_data(client_socket, 12)
    #we are receiving handshake packets
    server_seq_num, server_ack_num, ack_flag, syn_flag, fin_flag, payload = recv_data(client_socket, 12, True)

    #syn + ACK

    send_packet(client_socket, server_addr, server_seq_num+1, server_ack_num, '100')
   
    #handshake done

    #Decode the LoadBalancer's choice from the packet
    while True:
        with open(file_location, 'a') as f:
            #data, addr = client_socket.recvfrom(524)
            seq_num, ack_num, ack_flag, syn_flag, fin_flag, payload = recv_data(client_socket, 524, False)
            #for normal communication, all data is always sent with 010 flag
            f.write(payload.decode())
            loadBalancerChoice = payload.decode()
            if fin_flag:
                logging.info(f'Received FIN - done receiving data')
                print('Received FIN - done receiving data')
                return loadBalancerChoice
            #otherwise continue with next expected sequence
            send_packet(client_socket, server_addr, ack_num, seq_num+len(payload)+1-12, '100')

#Read the arguments from the command line and return the values
def get_args(argv=None):
    parser = argparse.ArgumentParser(description="ANONCLIENT")
    parser.add_argument('-s', type=str, required=True, help='Server IP')
    parser.add_argument('-p', type=int, required=True, help='Port')
    parser.add_argument('-l', type=str, required=True, help='logFile')
    parser.add_argument('-f', type=str, required=True, help='File to write to')
    args = parser.parse_args()
    server_ip = args.s
    server_port = args.p
    log_file = args.l    
    dest_file = args.f
    return server_ip, server_port, log_file, dest_file

def get_bit(num, i):
        return int((num & (1 << i)) != 0)

def update_bit(num, i, bit):
    num = 0 
    mask = ~(1 << i)
    return (num & mask) | (bit << i)

#Sends the packet
def send_packet(sock, server_address, seq_num, ack_num, flag_seq):
    flag_num = 0
    ack_flag = int(flag_seq[0])
    syn_flag = int(flag_seq[1])
    fin_flag = int(flag_seq[2])
    if ack_flag == 1:
        flag_num = update_bit(flag_num, 2, 1)
    if syn_flag == 1:
        flag_num = update_bit(flag_num, 1, 1)
    if fin_flag == 1:
        flag_num = update_bit(flag_num, 0, 1)

    data = struct.pack('>III', seq_num, ack_num, flag_num) 
    sock.sendto(data, server_address)
    logging.info(f"Sending: Seq num {seq_num} ACK num {ack_num}, ACK flag {ack_flag} SYN flag {syn_flag} FIN flag {fin_flag}")


#Receive the data
def recv_data(sock, size, handshake):
    if handshake:
        r_data = sock.recvfrom(12)
        data = r_data[0]
        conn = r_data[1]
        payload = ""
        seq, ack, flags = struct.unpack('>III', data)
        ack_flag = get_bit(flags,2)
        syn_flag = get_bit(flags,1)
        fin_flag = get_bit(flags,0)
        logging.info(f"Seq num {seq} ACK num {ack}, ACK flag {ack_flag} SYN flag {syn_flag} FIN flag {fin_flag}")
    else:
        r_data = sock.recvfrom(524)
        data = r_data[0]
        conn = r_data[1]
        new_formatter = '>III'+str(len(data)-12)+'s'
        seq, ack, flags, payload = struct.unpack(new_formatter, data)
        ack_flag = get_bit(flags,2)
        syn_flag = get_bit(flags,1)
        fin_flag = get_bit(flags,0)
        logging.info(f"Seq num {seq} ACK num {ack}, ACK flag {ack_flag} SYN flag {syn_flag} FIN flag {fin_flag}, Payload size: len((data)")
        print("Received Message. Payload Size: {}".format(len(payload)))
    return seq, ack, ack_flag, syn_flag, fin_flag, payload

#Main section of code
if __name__ == '__main__':
    #parse arguments
    server_ip, server_port, log_location, file_location = get_args(sys.argv[1:])
    print("Server IP: {}, Port: {}, Log location: {}, File Location: {} ".format(server_ip, server_port, log_location, file_location))

    #initialize the file

    f = open(file_location, 'w')
    f.close()

    #configure logging
    logging.basicConfig(filename=log_location, filemode='w', format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s', level=logging.INFO)
    logging.info(f'Starting ANONCLIENT')
    logging.info(f"Remote Server IP = {server_ip}, Remote Server Port = {server_port}, Logfile = {log_location}")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (server_ip, server_port)
    
    #Make contact with the LoadBalancer and store its preference in loadBalancerChoice
    loadBalancerChoice = meet_loadbalancer(client_socket, server_addr)

    #Update the target server address with the LoadBalancer's response, then proceed as normal
    server_addr = (loadBalancerChoice, server_port)

    #send initial sequence number
    client_seq = random.randint(0,4294967295) #0 to 2^32 -1, as in TCP
    print("Client Sequence Number:", client_seq)
    server_seq = 0

    #send first handshake packet
    #syn + ISN
    send_packet(client_socket, server_addr, client_seq, server_seq, '010')
    #receive SYN+ACK, SET REMOTE
    #seq_num, ack_num, flags  = recv_data(client_socket, 12)
    #we are receiving handshake packets
    server_seq_num, server_ack_num, ack_flag, syn_flag, fin_flag, payload = recv_data(client_socket, 12, True)

    #syn + ACK

    send_packet(client_socket, server_addr, server_seq_num+1, server_ack_num, '100')
   
    #handshake done

    #get data
    while True:
        with open(file_location, 'a') as f:
#            data, addr = client_socket.recvfrom(524)
            seq_num, ack_num, ack_flag, syn_flag, fin_flag, payload = recv_data(client_socket, 524, False)
            #for normal communication, all data is always sent with 010 flag
            f.write(payload.decode())
            if fin_flag:
                logging.info(f'Received FIN - done receiving data')
                print('Received FIN - done receiving data')
                sys.exit(0)
            #otherwise continue with next expected sequence
            send_packet(client_socket, server_addr, ack_num, seq_num+len(payload)+1-12, '100')




