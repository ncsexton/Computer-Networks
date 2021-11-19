import argparse
import socket
import struct
import threading
import sys
import logging
import time
import random
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
ENCODING = 'utf-8'


def get_args(argv=None):
    '''read the arguments from command line and return the values'''
    parser = argparse.ArgumentParser(description="REPLICASERVER")
    parser.add_argument('-p', type=int, required=True, help='Port')
    parser.add_argument('-l', type=str, required=True, help='logFile')
    parser.add_argument('-w', type=str, required=True, help='webserver')
    args = parser.parse_args()
    log_file = args.l
    server_port = args.p
    web_address = args.w
    return server_port, log_file, web_address

def get_bit(num, i):
    return (num & (1 << i)) != 0

def update_bit(num, i, bit):
    mask = ~(1 << i)
    return (num & mask) | (bit << i)

def send_packet(thread_id, conn, addr, data_packet):
    '''send packet to client'''
    try:
        conn.sendall(data_packet)
        logging.info(f"Thread ID: {thread_id}. Sent data {data_packet} to Addr: {addr} ")
        return 0
    except socket.error as e:
        logging.error(f"Error: Sending packet to:{addr}, Error:{e}")
        sys.exit(1)

def unpack_header(thread_id, formatter, header):
    '''Unpack a header and return the values'''
    try:
        seq, ack, flags = struct.unpack(formatter, header)
    except struct.error as e:
        logging.error(f"Error unpacking data. Error:{e}")
        print("Error unpacking data in thread {}. Exiting thread.".format(thread_id))
        sys.exit(1)

    ack_flag = 0
    syn_flag = 0
    fin_flag = 0

    if get_bit(flags, 0):
        fin_flag = 1
    if get_bit(flags, 1):
        syn_flag = 1
    if get_bit(flags, 2):
        ack_flag = 1

    logging.info(f"Seq: {seq}, ACK: {ack}, ACK_FLAG:{ack_flag}, SYN_FLAG: {syn_flag}, FIN_FLAG:{fin_flag}")
    return seq, ack, ack_flag, syn_flag, fin_flag


def send_full_packet(sock, client_address, seq_num, ack_num, flag_seq, data_to_send):
    '''send packet'''
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
    data += data_to_send.encode()
    sock.sendto(data, client_address)

    logging.info(f"Sending packet with Seq num: {seq_num} ACK num: {ack_num}, ACK flag: {ack_flag} SYN flag: {syn_flag}, FIN flag: {fin_flag}, Payload size: len(data_to_send)")
    print("Sending packet with Seq num: {} ACK num: {}, ACK flag: {} SYN flag: {}, FIN flag: {}, Payload size: {}".format(seq_num, ack_num, ack_flag, syn_flag, fin_flag, len(data_to_send)))

def handle_client(server_socket,client_addr, data, web_object, conn_dict):
    '''Handling a client connection. One thread per client connection.'''
    thread_id = threading.get_ident()
    print("Thread ID {} is handling connection from {}".format(thread_id, client_addr))
    logging.info(f"Thread ID: {thread_id}. Handling a connection from: {address}")
    client_seq, client_ack, ack_bit, syn_bit, fin_bit = unpack_header(thread_id, '>III', data)
    conn_dict_count = conn_dict[client_addr]

    logging.info(f"Seq num {client_seq} ACK num {client_ack}, ACK flag {ack_bit} SYN flag {syn_bit} FIN flag {fin_bit}")
    data_to_send = ""

    #first two messages are for handshake
    payload_start_index = (conn_dict_count-2)*512
    if payload_start_index + 512 > len(web_object):
        payload_end_index = len(web_object)
    else:
        payload_end_index = payload_start_index + 512
    logging.debug("Payload start index: {payload_start_index}, Payload End Index: {payload_end_index}")

    if not ack_bit and syn_bit: #first handshake 
        seq_to_send = random.randint(0,4294967295) #0 to 2^32 -1, as in TCP
        ack_to_send = client_seq + 1
        flag_seq = '110'
        send_full_packet(server_socket, client_addr, seq_to_send, ack_to_send, flag_seq, data_to_send)
    else:
        seq_to_send = client_ack
        ack_to_send = client_seq + 1
        if (payload_end_index - payload_start_index) == 512:
            data_to_send = web_object[payload_start_index:payload_end_index]
            flag_seq = '100'
        if (payload_end_index - payload_start_index) < 512:
            data_to_send = web_object[payload_start_index:payload_end_index]
            flag_seq = '101' #set the fin bit
        send_full_packet(server_socket, client_addr, seq_to_send, ack_to_send, flag_seq, data_to_send)


def get_webpage(web_addr):
    req = Request(web_addr)
    try:
        response = urlopen(req)
        # we are converting the page to an URL for simplicity here.
        page = str(response.read())
    except HTTPError as e:
        logging.error(f"Error: Downloading page from: {web_addr}, Error:{e}")
    except URLError as e:
        logging.error(f"Error: Downloading page from: {web_addr}, Error:{e}")
    else:
        logging.info(f"Success downloading page from: {web_addr}")
        return page

if __name__ == '__main__':
    '''main function'''
    #parse arguments
    port, log_location, web_addr = get_args(sys.argv[1:])
    print("Port: {}, Log location: {}, Web Address: {}".format(port, log_location, web_addr))

    #configure logging
    logging.basicConfig(filename=log_location, filemode='w', format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s', level=logging.INFO)
    logging.info('Starting LIGHTSERVER')
    logging.info(f"Server Port = {port}, Logfile = {log_location}, Web Address = {web_addr}")

    #get the local IP. You might have to adjust it depending on where you are running this.
    my_ip = socket.gethostbyname(socket.gethostname())
    logging.info(f"Server IP = {my_ip}")

    #create socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logging.info(f"Success: Created socket on IP:{my_ip}, Port:{port}")
    except socket.error as e:
        logging.error(f"Error: Creating socket on IP:{my_ip}, Port:{port}, Error:{e}")
        sys.exit(1)

    #bind it to the ip and port
    try:
        server_socket.bind((my_ip,port))
        logging.info(f"Success:Bind Successful")
    except socket.error as e:
        logging.error(f"Error: Binding socket to IP:{my_ip}, Port:{port}, Error:{e}")
        sys.exit(1)

    #download the web object
    web_object = get_webpage(web_addr)

    #start handling clients, keep track of how many objects are sent per connection
    conn_dict = {}

    while True:
        #client initiated new conversation. We know about fixed length header. Rest 
        #we will handle in the thread
        data, address = server_socket.recvfrom(524)
        if address not in conn_dict:
            conn_dict[address] = 1 #first packet
        else:
            conn_dict[address] += 1

        logging.info(f"Received a message from: {address}")
        thread = threading.Thread(target=handle_client, args=(server_socket, address, data, web_object, conn_dict))
        thread.start()
