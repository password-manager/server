import socket
import random
import string
from threading import Thread
from pyisemail import is_email
import smtplib, ssl
import json

HOST = '127.0.0.1'
PORT = 8887
SSL_PORT = 465
SMTP_SERVER = "smtp.gmail.com"
SENDER_EMAIL = "aghpassman@gmail.com"

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
            code = self.generateVerificationCode(msg)
            self.sendMailWithVerificationCode(msg, code)

    def isClientAlreadyRegistered(self, msg):
        with open("registeredClients.txt", "r") as f:
            lines = f.read().splitlines()
        clients = []
        for line in lines:
            clients.append(line.split(":")[0])
        mail = msg.split(":")[0]
        if mail in clients:
            return True
        return False

    def verifyClientEmail(self, msg):
        address, _ = msg.split(":")
        return is_email(address, check_dns=False)

    def generateVerificationCode(self, msg):
        generatedCode = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))
        with open("registeringClients.txt", "a+") as f:
            f.write(msg + ":" + generatedCode + "\n")
        return generatedCode

    def sendMailWithVerificationCode(self, msg, code):
        receiver_email, _ = msg.split(":")
        message = """\
        Verification code

        This is your verification code: """ + code

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SSL_PORT, context=context) as server:
            server.login(SENDER_EMAIL, PASSWORD)
            server.sendmail(SENDER_EMAIL, receiver_email, message)
        print("(L)Email with verification code sent")

    def verifyRegistration(self, msg):
        if not self.checkVerificationCode(msg):
            print("(L)Verification code incorrect")
        else:
            self.addNewClient(msg)
            print("(L)Successful registration")
            self.sendRegistrationConfirmation()

    def checkVerificationCode(self, msg): # todo - poprawic sprawdzanie i obsluge pliku
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

        f = open("databases/" + mail + ".json", "w+")
        f.write("[]")
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

    def storeLogs(self, messageLogs):
        if self.clientLogin:
            with open("databases/" + self.clientLogin + ".json", "r+") as file:
                fileLogs = file.read()
                logs = json.loads(fileLogs) + json.loads(messageLogs)
                file.seek(0)
                json.dump(logs, file)

    def synchronize(self, clientTimestamp):
        if self.clientLogin:
            with open("databases/" + self.clientLogin + ".json", "r") as file:
                allLogs = json.loads(file.read())
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
