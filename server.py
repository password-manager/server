import sys
import socket
import selectors
import types

HOST = '127.0.0.1'
PORT = 8888

selector = selectors.DefaultSelector()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

clientsAddresses = {}

connections = {}

def acceptConnection(sock):
    connection, addr = sock.accept()
    connections[addr] = connection
    connection.setblocking(False)
    print(connection)
    print("(L) Connection from ", addr)
    data = types.SimpleNamespace(addr = addr, inb = b"", outb = b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    selector.register(connection, events, data = data)    

def serviceConnection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        print("(L) Message from: ", data.addr)
        if recv_data:
            manageMessage(recv_data, data)
        else:
            print("(L) Closing connection to ", data.addr)
            selector.unregister(sock)
            sock.close()

def manageMessage(msg, senderData):
    msg = msg.decode("utf-8")
    msg_id = msg[0]
    msg = msg[2:]

    if msg_id == "0":
        registerClient(msg, senderData)
    if msg_id == "1":
        verifyRegistration(msg, senderData)
    if msg_id == "2":
        loginClient(msg, senderData)
    if msg_id == "3":
        storeLogs(msg, senderData)
    if msg_id == "4":
        synchronizing(msg, senderData)
#rejestracja -> tworzymy plik z logami dla danego klienta + mapujemy adres ip klienta z id klienta
#logowanie -> mapujemy ip z id klienta
#zerwanie polaczenia -> usuwamy z listy adresów klienta dane ip ?

def mapClientAddress(clientName, address):
    clientsAddresses[address] = clientName    # mapujemy ip -> klient (jeden klient moze miec wiele ip)

def checkVerificationCode(msg): #todo - mądrzejsze sprawdzanie?
    f = open("registeringClients.txt", "r")
    lines = f.read().splitlines()
    isVerified = False
    if msg in lines:
        isVerified = True
    f.close()
    return isVerified

def addNewClient(msg, clientData):
    mail, password, _ = msg.split(":")
    f = open("registeredClients.txt", "a+")
    f.write(mail + ":" + password + "\n")
    f.close()
    #todo - usuwanie z registeringClients.txt
    mapClientAddress(mail, clientData.addr)

    f = open(mail + ".txt", "w+")
    f.close()

def verifyRegistration(msg, senderData):
    if not checkVerificationCode(msg):
        print("Verification code incorrect")
    else:
        addNewClient(msg, senderData)
        print("successfull registration")
        sendRegistrationConfirmation(senderData)

def sendRegistrationConfirmation(senderData):
    data = "0:registrationConfirmation"
    data = bytes(data, 'utf-8')
    getSocket(senderData.addr).send(data)

def isClientAlreadyRegistered(msg): #todo - sprawdzac tylko po mailu
    f = open("registeredClients.txt", "r")
    lines = f.read().splitlines()
    if msg in lines:
        return True
    return False

def verifyClientEmail(msg):
    mail, _ = msg.split(":")
    print("veryfying mail: " + mail + " - todo")

def generateAndSaveVerificationCode(msg):
    generatedCode = "generatedCode" #todo - generating
    f = open("registeringClients.txt", "a+")
    f.write(msg + ":" + generatedCode + "\n")
    f.close()
    return generatedCode

def sendMailWithVerificationCode(msg, code, clientData):
    print("sending code: " + code + " - todo")

def registerClient(msg, clientData):
    if isClientAlreadyRegistered(msg):
        print("Client already registered")
    else:
        verifyClientEmail(msg)
        code = generateAndSaveVerificationCode(msg)
        sendMailWithVerificationCode(msg, code, clientData)


def verifyPassword(clientLogin, clientPassword): #todo - ???
    f = open("registeredClients.txt", "r")
    clients = f.read().splitlines()
    clients = dict(map(lambda s : s.split(':'), clients))

    isPasswordCorrect = False
    for login, password in clients.items():
        if login == clientLogin:
            if password != clientPassword:
                print("incorrect password")
            else:
                isPasswordCorrect = True
    f.close()
    return isPasswordCorrect

def loginClient(msg, senderData):
    login, password = msg.split(":")
    if verifyPassword(login, password):
        mapClientAddress(login, senderData.addr)
        print("login successful")
        sendLoginConfirmation(senderData)

def sendLoginConfirmation(senderData):
    data = "1:loginConfirmation"
    data = bytes(data, 'utf-8')
    getSocket(senderData.addr).send(data)

def storeLogs(logs, clientData):  #todo - zabezpieczenie przed niezalogowanymi klientami
    f = open(clientsAddresses[clientData.addr] + ".txt", "a+")
    f.write(logs + "\n")
    f.close()

    
def synchronizing(msg, clientData):
    synchTimestamp = int(msg)
    f = open(clientsAddresses[clientData.addr] + ".txt", "r")
    lines = f.readlines()
    for line in lines:
        timestamp, logs = line.split(":")
        timestamp = int(timestamp)
        if timestamp > synchTimestamp:
            sendData = bytes(str(timestamp) + ":" + logs[:-1], 'utf-8')
            print("send_data: ", sendData)
            print("address: ", clientData.addr)
            #should also send timestamp
            getSocket(clientData.addr).send(sendData)
            print("should send log: ", logs)

def getSocket(addr):
   return connections[addr]

if __name__=='__main__':    
    sock.bind((HOST, PORT))
    sock.listen()
    sock.setblocking(False)
    selector.register(sock, selectors.EVENT_READ)
    print("(L) Ready for connection")
    
    while True:
        try:
            events = selector.select(timeout = None)
            for key, mask in events:
                if key.data is None:
                    acceptConnection(key.fileobj)
                else:
                    serviceConnection(key, mask)
        except KeyboardInterrupt:
            selector.close()
            sys.exit()                
