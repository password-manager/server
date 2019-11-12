import socket
import random
import string
from threading import Thread
from pyisemail import is_email
import smtplib, ssl
import json

#todo - move to some config file
HOST = '127.0.0.1'
PORT = 8887
SSL_PORT = 465
SMTP_SERVER = "smtp.gmail.com"
SENDER_EMAIL = "aghpassman@gmail.com"
PASSWORD = "strongestPasswordEver"

class ClientThread(Thread):
    def __init__(self, addr):
        Thread.__init__(self)
        self.addr = addr
        self.clientLogin = ""
        print("(L)New connection on: ", addr)

    def run(self):
        while True:
            recvData = conn.recv(2048)
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
            self.synchronize(int(msg))

    def sendErrorMsg(self, msg):
        data = bytes(msg, 'utf-8')
        conn.send(data)
        print("(L)" + msg)

    def registerClient(self, msg):
        if self.isClientAlreadyRegistered(msg):
            self.sendErrorMsg("Client with given email is already registered")
        elif not self.verifyClientEmail(msg):
            self.sendErrorMsg("Email address not valid")
        else:
            print("(L)Email is valid")
            code = self.generateVerificationCode()
            self.saveClientData(msg, code)
            self.sendMailWithVerificationCode(msg, code)

    def isClientAlreadyRegistered(self, msg):
        with open("registeredClients.json", "r") as file:
            clients = json.load(file)
            client = [x for x in clients if x['login'] == msg.split(":")[0]]
            if client:
                return True
            return False

    def verifyClientEmail(self, msg):
        address, _, _ = msg.split(":")
        return is_email(address, check_dns=False)

    def generateVerificationCode(self):
        return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))

    def saveClientData(self, msg, code):#todo - sprawdzic czy juz istnieje i ewentualnie podmienic
        login, hash, salt = msg.split(":")
        newClient = "[{\"login\": \"" + login + "\", \"hash\": \"" + hash + "\", \"salt\": \"" + salt + "\", \"code\": \"" + code + "\"}]"
        print ("(L)New client: ", newClient)
        with open("registeringClients.json", "r+") as file:
            fileClients = file.read()
            clients = json.loads(fileClients) + json.loads(newClient)
            file.seek(0)
            json.dump(clients, file)

    def sendMailWithVerificationCode(self, msg, code):
        receiver_email, _, _ = msg.split(":")
        message = """\
        Verification code

        This is your verification code: """ + code

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SSL_PORT, context=context) as server:
            server.login(SENDER_EMAIL, PASSWORD)
            server.sendmail(SENDER_EMAIL, receiver_email, message)
        print("(L)Email with verification code sent")

    def verifyRegistration(self, msg): #todo - sprawdzanie hasła
        if not self.checkVerificationCode(msg):
            print("(L)Verification code incorrect")
        else:
            self.addNewClient(msg)
            print("(L)Successful registration")
            self.sendRegistrationConfirmation()

    def checkVerificationCode(self, msg):
        login, _, code = msg.split(":")
        with open("registeringClients.json", "r") as file:
            clients = json.load(file)
            client = ([x for x in clients if x['login'] == login])[0]
            if client['code'] == code:
                return True
            return False

    def addNewClient(self, msg):
        login, _, _ = msg.split(":")
        with open("registeringClients.json", "r") as file:
            clients = json.load(file)
            client = ([x for x in clients if x['login'] == login])[0]
            hash = client['hash']
            salt = client['salt']
            #todo - usuwanie z registeringClients

        newClient = "[{\"login\": \"" + login + "\", \"hash\": \"" + hash + "\", \"salt\": \"" + salt + "\"}]"
        print ("(L)New client: ", newClient)
        with open("registeredClients.json", "r+") as file:
            clients = json.load(file) + json.loads(newClient)
            file.seek(0)
            json.dump(clients, file)

        with open("databases/" + login + ".json", "w+") as file:
            file.write("[]")

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

    def verifyPassword(self, login, password):  # todo - hash z hasła -> porównujemy
        with open("registeredClients.json", "r") as file:
            clients = json.load(file)
            client = [x for x in clients if x['login'] == login][0]
            if client['hash'] == password:
                return True
            return False

    def sendLoginConfirmation(self):
        data = "1:loginConfirmation"
        data = bytes(data, 'utf-8')
        conn.send(data)

    def storeLogs(self, messageLogs):
        if self.clientLogin:
            with open("databases/" + self.clientLogin + ".json", "r+") as file:
                logs = json.load(file) + json.loads(messageLogs)
                file.seek(0)
                json.dump(logs, file)

    def synchronize(self, clientTimestamp):
        if self.clientLogin:
            with open("databases/" + self.clientLogin + ".json", "r") as file:
                allLogs = json.load(file)
                filteredLogs = [log for log in allLogs if log['timestamp'] > clientTimestamp]
                conn.send(bytes(json.dumps(filteredLogs), 'utf-8'))

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
