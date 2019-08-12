#!/usr/bin/env python3

import sys
import socket
import selectors
import types

HOST = '127.0.0.1'  
PORT = 8888

selector = selectors.DefaultSelector()

def accept_connection(sock):
    connection, addr = sock.accept()
    connection.setblocking(False)
    print("Connection from ", addr)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ
    selector.register(connection, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if recv_data:
            print(recv_data)
        else:
            print("Closing connection to ", data.addr)
            selector.unregister(sock)
            sock.close()

            
if __name__=='__main__':    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen()
    sock.setblocking(False)
    selector.register(sock, selectors.EVENT_READ)

    print("Ready for connection")
    
    try:
        while True:
            events = selector.select(timeout = None)
            for key, mask in events:
                if key.data is None:
                    accept_connection(key.fileobj)
                else:
                    service_connection(key, mask)
    except KeyboardInterrupt:
        print("Keyboard Interrupt")
    finally:
        selector.close()
                    