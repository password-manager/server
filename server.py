import socket
import random
import string
from threading import Thread
from pyisemail import is_email
import smtplib, ssl
import json
import hashlib
import base64
import os

#todo - move to some config file
HOST = '127.0.0.1'
PORT = 8887
SSL_PORT = 465
SMTP_SERVER = "smtp.gmail.com"
SENDER_EMAIL = "aghpassman@gmail.com"
PASSWORD = "strongestPasswordEver"

SALT = hashlib.sha256(os.urandom(64)).hexdigest().encode('ascii')

class ClientThread(Thread):
    def __init__(self, addr):
        Thread.__init__(self)
        self.addr = addr
        self.clientLogin = ""
        self.conn = conn
        print("(L)New connection on: ", addr)

    def run(self):
        while True:
            recvData = self.conn.recv(2048)
            if recvData:
                self.manageMessage(recvData)
            else:
                print("(L)Closing connection to ", addr)
                self.conn.close()

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
            self.synchronize(int(msg))
        if msg_id == "4":
            self.storeLogs(msg)

    def registerClient(self, msg):
        if self.isClientAlreadyRegistered(msg):
            self.sendRegistrationResponse("notOk", "Client with given email is already registered")
        elif not self.verifyClientEmail(msg):
            self.sendRegistrationResponse("notOk", "Email address not valid")
        else:
            print("(L)Email is valid")
            code = self.generateVerificationCode()
            self.saveClientData(msg, code)
            self.sendMailWithVerificationCode(msg, code)
            self.sendRegistrationResponse("ok", "Email with verification code sent")

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
        login, passw, salt = msg.split(":")
        #salt = bytes(salt, 'utf-8')
        newClient = "[{\"login\": \"" + login + "\", \"hash\": \"" + self.generateHash(passw, bytes(salt, 'utf-8')) + "\", \"salt\": \"" + salt + "\", \"code\": \"" + code + "\"}]"
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

    def sendRegistrationResponse(self, status, msg):
        data = "0:" + status + ":" + msg
        data = bytes(data, 'utf-8')
        print("(L)sending on connection: ", conn)
        self.conn.send(data)

    def verifyRegistration(self, msg): #todo - sprawdzanie hasła
        if not self.checkVerificationCode(msg):
            print("(L)Verification code incorrect")
            self.sendRegistrationVerificationResponse("notOk", "Verification code incorrect")
        else:
            self.addNewClient(msg)
            print("(L)Successful registration")
            self.sendRegistrationVerificationResponse("ok", "Succesfull registration")

    def checkVerificationCode(self, msg):
        login, _, code = msg.split(":")
        with open("registeringClients.json", "r") as file:
            clients = json.load(file)
            client = ([x for x in clients if x['login'] == login])[0]
            print(client['code'])
            print(code)
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
            #salt = bytes(salt, 'utf-8')
            #todo - usuwanie z registeringClients

        newClient = "[{\"login\": \"" + login + "\", \"hash\": \"" + hash + "\", \"salt\": \"" + salt + "\"}]"
        print ("(L)New client: ", newClient)
        with open("registeredClients.json", "r+") as file:
            clients = json.load(file) + json.loads(newClient)
            file.seek(0)
            json.dump(clients, file)

        with open("databases/" + login + ".json", "w+") as file:
            file.write("[]")

    def sendRegistrationVerificationResponse(self, status, msg):
        data = "1:" + status + ":" + msg
        data = bytes(data, 'utf-8')
        print("(L)sending on connection: ", conn)
        self.conn.send(data)

    def loginClient(self, msg):
        login, password = msg.split(":")
        if self.verifyPassword(login, password):
            print("(L)Login successful")
            self.sendLoginResponse("ok", "Login successful")
            self.clientLogin = login
        else:
            print("(L)Login unsuccessful")
            self.sendLoginResponse("notOk", "Login unsuccessful - wrong password") #TODO - inne kozy

    def verifyPassword(self, login, password):  # todo - hash z hasła -> porównujemy
        with open("registeredClients.json", "r") as file:
            clients = json.load(file)
            client = [x for x in clients if x['login'] == login][0]
            if client['hash'] == self.generateHash(password, bytes(client['salt'],'utf-8')):
                return True
            return False

    def generateHash(self, password, salt):
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                      salt, 100000, dklen=64)
        pwdhash = base64.b64encode(pwdhash)
        return pwdhash.decode()

    def sendLoginResponse(self, status, msg):
        data = "2:" + status + ":" + msg
        print("(L)sending on connection: ", conn)
        data = bytes(data, 'utf-8')
        self.conn.send(data)

    def storeLogs(self, messageLogs):
        if self.clientLogin:
            with open("databases/" + self.clientLogin + ".json", "r+") as file:
                logs = json.load(file) + json.loads(messageLogs)
                file.seek(0)
                json.dump(logs, file)
                self.sendSynchronizationResponse("ok", "")

    def sendSynchronizationResponse(self, status, msg):
        data = "4:" + status + ":" + msg
        print("(L)sending on connection: ", conn)
        data = bytes(data, 'utf-8')
        self.conn.send(data)

    def synchronize(self, clientTimestamp):
        if self.clientLogin:
            with open("databases/" + self.clientLogin + ".json", "r") as file:
                allLogs = json.load(file)
                filteredLogs = [log for log in allLogs if log['timestamp'] > clientTimestamp]
                print("sending logs to: ", conn)
                print("logs: ", filteredLogs)
                if filteredLogs:
                    print("sending on connection: ", conn)
                    self.conn.send(bytes("3:" + json.dumps(filteredLogs), 'utf-8'))

if __name__=='__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))

    clientThreads = []
    clientSockets = {}

    print("(L)Ready for connection")
    while True:
        server.listen()
        (conn, addr) = server.accept()
        newClient = ClientThread(addr)
        newClient.start()
        clientThreads.append(newClient)
