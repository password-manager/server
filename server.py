
import socket
from threading import Thread

HOST = '127.0.0.1'
PORT = 8888

class ClientThread(Thread):
    def __init__(self, addr):
        Thread.__init__(self)
        self.addr = addr
        self.clientLogin = ""
        print("(L)New connection on: ", addr)

    def run(self):
        while True:
            recvData = conn.recv(2048) #TODO - how big can messages be
            if recvData:
                self.manageMessage(recvData)
            else:
                print("(L)Closing connection to ", addr)
                conn.close()

    def manageMessage(self, msg):
        msg = msg.decode("utf-8")
        msg_id = msg[0]
        msg = msg[2:]

        if msg_id == "0":
            self.registerClient(msg)
        if msg_id == "1":
            self.verifyRegistration(msg)
        if msg_id == "2":
            self.loginClient(msg)
        if msg_id == "3":
            self.storeLogs(msg)
        if msg_id == "4":
            self.synchronize(msg)

    def registerClient(self, msg):
        if self.isClientAlreadyRegistered(msg):
            print("(L)Client with given email already exists")
        else:
            self.verifyClientEmail(msg)
            code = self.generateVerificationCode(msg)
            self.sendMailWithVerificationCode(code)

    def isClientAlreadyRegistered(self, msg): #todo - sprawdzac tylko po mailu + sprawdzać też w registeringClients
        f = open("registeredClients.txt", "r")
        lines = f.read().splitlines()
        if msg in lines:
            return True
        return False

    def verifyClientEmail(self, msg): #todo - sprawdzać syntax i czy mail istnieje
        mail, _ = msg.split(":")
        print("veryfying mail: " + mail + " - todo")

    def generateVerificationCode(self, msg):
        generatedCode = "generatedCode" #todo - generating
        f = open("registeringClients.txt", "a+")
        f.write(msg + ":" + generatedCode + "\n")
        f.close()
        return generatedCode

    def sendMailWithVerificationCode(self, code):
        print("sending code: " + code + " - todo")

    def verifyRegistration(self, msg):
        if not self.checkVerificationCode(msg):
            print("(L)Verification code incorrect")
        else:
            self.addNewClient(msg)
            print("(L)Successful registration")
            self.sendRegistrationConfirmation()

    def checkVerificationCode(self, msg):  # todo - lepsze sprawdzanie i obsługa pliku
        f = open("registeringClients.txt", "r")
        lines = f.read().splitlines()
        isVerified = False
        if msg in lines:
            isVerified = True
        f.close()
        return isVerified

    def addNewClient(self, msg):
        mail, password, _ = msg.split(":")
        f = open("registeredClients.txt", "a+")
        f.write(mail + ":" + password + "\n")
        f.close()
        #self.clientLogin = mail
        # todo - usuwanie z registeringClients.txt
        #mapClientAddress(mail, addr)

        f = open(mail + ".txt", "w+")
        f.close()

    def sendRegistrationConfirmation(self):
        data = "0:registrationConfirmation"
        data = bytes(data, 'utf-8')
        conn.send(data)

    def loginClient(self, msg):
        login, password = msg.split(":")
        if self.verifyPassword(login, password):
            print("(L)Login successful")
            self.sendLoginConfirmation()
            self.clientLogin = login
        else:
            print("(L)Login unsuccessful")

    def verifyPassword(self, clientLogin, clientPassword):  # todo - ???
        f = open("registeredClients.txt", "r")
        clients = f.read().splitlines()
        clients = dict(map(lambda s: s.split(':'), clients))

        isPasswordCorrect = False
        for login, password in clients.items():
            if login == clientLogin:
                if password != clientPassword:
                    print("incorrect password")
                else:
                    isPasswordCorrect = True
        f.close()
        return isPasswordCorrect

    def sendLoginConfirmation(self):
        data = "1:loginConfirmation"
        data = bytes(data, 'utf-8')
        conn.send(data)

    def storeLogs(self, logs):
        if self.clientLogin:
            f = open(self.clientLogin + ".txt", "a+")
            f.write(logs + "\n")
            f.close()

    def synchronize(self, msg):
        synchTimestamp = int(msg)
        if self.clientLogin:
            f = open(self.clientLogin + ".txt", "r")
            lines = f.readlines()
            for line in lines:
                timestamp, logs = line.split(":")
                timestamp = int(timestamp)
                if timestamp > synchTimestamp:
                    sendData = bytes(str(timestamp) + ":" + logs[:-1], 'utf-8')
                    print("send_data: ", sendData)
                    print("address: ", self.addr)
                    conn.send(sendData)
                    print("should send log: ", logs)


if __name__=='__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))

    clientThreads = []

    print("(L)Ready for connection")
    while True:
        server.listen()
        (conn, addr) = server.accept()
        newClient = ClientThread(addr)
        newClient.start()
        clientThreads.append(newClient)
