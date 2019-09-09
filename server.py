#!/usr/bin/env python3

import sys
import socket
import selectors
import types

HOST = '127.0.0.1'  
PORT = 8888

logs = {}

selector = selectors.DefaultSelector()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    
clients_addresses = {}

def accept_connection(sock):
    connection, addr = sock.accept()
    connection.setblocking(False)
    print("Connection from ", addr)
    data = types.SimpleNamespace(addr = addr, inb = b"", outb = b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    selector.register(connection, events, data = data)    

    
def service_connection(key, mask):
    sock = key.fileobj  #osobny sock klienta?
    #print("client socket: ", sock)
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        print("message from: ", data.addr)
        if recv_data:
            manage_message(recv_data, data)
        else:
            print("Closing connection to ", data.addr)
            selector.unregister(sock)
            sock.close()

            
def manage_message(data, client_data):
    data = data.decode("utf-8")
    flag = data[0]
    data = data[1:]
    if flag == "R": #register
        register_client(data, client_data)
    if flag == "L": #login
        login_client(data, client_data)
    if flag == "U": #update server
        storing_logs(data, client_data)  
    if flag == "S": #synchronize
        synchronizing(data, client_data)
#rejestracja -> tworzymy plik z logami dla danego klienta + mapujemy adres ip klienta z id klienta
#logowanie -> mapujemy ip z id klienta
#zerwanie polaczenia -> usuwamy z listy adresów klienta dane ip


def register_client(data, client_data):
    if isClientAlreadyRegistered(data):
        print("registration denied") #TODO - zamknąć połączenie 
    else:
        f = open("clients.txt", "a+")
        f.write(data + "\n")
        f.close()
    
        map_client_address(data, client_data.addr)
        #clients_addresses[client_data.addr] = data    # mapujemy ip -> klient (jeden klient moze miec wiele ip)
        #print("clients: ", clients_addresses)

        f = open(data + ".txt", "w+")
        f.close()
  
def login_client(data, client_data):
    if not isClientAlreadyRegistered(data):
        print("no such client")  
    else:
        map_client_address(data, client_data.addr)
 

def map_client_address(client_name, address):
    clients_addresses[address] = client_name    # mapujemy ip -> klient (jeden klient moze miec wiele ip)
    print("clients: ", clients_addresses)   
 
def isClientAlreadyRegistered(client_name):
    f = open("clients.txt", "r")
    print("client name:",client_name)
    clients = f.read().splitlines()
    print("clients: ", clients)
    flag = False
    if client_name in clients:
        flag = True			
    f.close()
    return flag		
            			
 
def storing_logs(data, client_data):
    print("We've received some logs - we need to store them")
    f = open(clients_addresses[client_data.addr] + ".txt", "a+")
    f.write(data + "\n")
    f.close()

    
def synchronizing(data, client_data):
    print("We will synchronize - sending new logs to client")
    current_timestamp = int(data)
    print("timestamp: ", current_timestamp)
    f = open(clients_addresses[client_data.addr] + ".txt", "r")
    logs = f.readlines()
    for log in logs:
        timestamp = int(log[0:10])
        log_data = log[10:]
        if timestamp > current_timestamp:
            send_data = bytes(log, 'utf-8')
            #s.sendall(data2)
            print("send_data: ", send_data)
            print("address: ", client_data.addr)
            #sock.sendto(send_data, client_data.addr)
            print("should send log: ", log_data)

    

            
if __name__=='__main__':    
    sock.bind((HOST, PORT))
    #print("server socket: ", socket.fileno())
    sock.listen()
    sock.setblocking(False)
    selector.register(sock, selectors.EVENT_READ)
    print("Ready for connection")
    
    while True:
        try:
            events = selector.select(timeout = None)
            for key, mask in events:
                if key.data is None:
                    accept_connection(key.fileobj)
                else:
                    service_connection(key, mask)
        except KeyboardInterrupt:
            selector.close()
            sys.exit()                
                    