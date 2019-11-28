import socket
import random
import string
from threading import Thread
from pyisemail import is_email
import smtplib
import json
import hashlib
import base64
import ssl
import keyring
#import getpass

class ClientThread(Thread):
    def __init__(self, addr):
        Thread.__init__(self)
        self.addr = addr
        self.client_login = ""
        self.conn = conn
        print("(L)New connection on: ", addr)

    def run(self):
        while True:
            recv_data = self.conn.recv(2048) #TODO - what size?
            if recv_data:
                self.manage_message(recv_data)
            else: #TODO - something more?
                print("(L)Closing connection to: ", addr)
                self.conn.close()

    def manage_message(self, msg):
        msg = msg.decode("utf-8")
        msg_id = msg[0]
        msg = msg[2:]

        if msg_id == "0":
            self.register_client(msg)
        if msg_id == "1":
            self.verify_registration(msg)
        if msg_id == "2":
            self.login_client(msg)
        if msg_id == "3":
            self.synchronize(int(msg))
        if msg_id == "4":
            self.store_logs(msg)

    def register_client(self, msg):
        if self.is_client_already_registered(msg):
            self.send_registration_response("notOk", "Client with given email is already registered")
        elif not self.verify_client_email(msg):
            self.send_registration_response("notOk", "Email address is not valid")
        else:
            print("(L)Email is valid")
            code = self.generate_verification_code()
            self.save_client_data(msg, code)
            self.send_mail_with_verification_code(msg, code)
            self.send_registration_response("ok", "Email with verification code sent")

    def is_client_already_registered(self, msg):
        with open("registeredClients.json", "r") as file:
            clients = json.load(file)
            client = [x for x in clients if x['login'] == msg.split(":")[0]]
            if client:
                return True
            return False

    def verify_client_email(self, msg):
        address, _, _ = msg.split(":")
        return is_email(address, check_dns=False) #TODO - na True

    def generate_verification_code(self):
        return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))

    def save_client_data(self, msg, code):#todo - sprawdzic czy juz istnieje i ewentualnie podmienic
        login, passw, salt = msg.split(":")
        newClient = "[{\"login\": \"" + login + "\", \"hash\": \"" + self.generate_hash(passw, bytes(salt, 'utf-8')) + "\", \"salt\": \"" + salt + "\", \"code\": \"" + code + "\"}]"
        print ("(L)New client: ", newClient)
        with open("registeringClients.json", "r+") as file:
            fileClients = file.read()
            clients = json.loads(fileClients) + json.loads(newClient)
            file.seek(0)
            json.dump(clients, file)

    def send_mail_with_verification_code(self, msg, code):
        port, server, mail = get_server_config("config.json")
        receiver_email, _, _ = msg.split(":")
        message = """\
        Verification code

        This is your verification code: """ + code

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(server, port, context=context) as server:
            server.login(mail, keyring.get_password("server", "password"))
            server.sendmail(mail, receiver_email, message)
        print("(L)Email with verification code sent")

    def send_registration_response(self, status, msg):
        data = "0:" + status + ":" + msg
        data = bytes(data, 'utf-8')
        print("(L)sending on connection: ", conn)
        self.conn.send(data)

    def verify_registration(self, msg): #todo - sprawdzanie hasła
        if not self.check_verification_code(msg):
            print("(L)Verification code incorrect")
            self.send_registration_verification_response("notOk", "Verification code incorrect")
        else:
            self.add_new_client(msg)
            print("(L)Successful registration")
            self.send_registration_verification_response("ok", "Succesfull registration")

    def check_verification_code(self, msg):
        login, _, code = msg.split(":")
        with open("registeringClients.json", "r") as file:
            clients = json.load(file)
            client = ([x for x in clients if x['login'] == login])[0]
            print(client['code'])
            print(code)
            if client['code'] == code:
                return True
            return False

    def add_new_client(self, msg):
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

    def send_registration_verification_response(self, status, msg):
        data = "1:" + status + ":" + msg
        data = bytes(data, 'utf-8')
        print("(L)sending on connection: ", conn)
        self.conn.send(data)

    def login_client(self, msg):
        login, password = msg.split(":")
        if self.verify_password(login, password):
            print("(L)Login successful")
            self.send_login_response("ok", "Login successful")
            self.client_login = login
        else:
            print("(L)Login unsuccessful")
            self.send_login_response("notOk", "Login unsuccessful - wrong password") #TODO - inne kozy

    def verify_password(self, login, password):  # todo - hash z hasła -> porównujemy
        with open("registeredClients.json", "r") as file:
            clients = json.load(file)
            client = [x for x in clients if x['login'] == login][0]
            if client['hash'] == self.generate_hash(password, bytes(client['salt'],'utf-8')):
                return True
            return False

    def generate_hash(self, password, salt):
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                      salt, 100000, dklen=64)
        pwdhash = base64.b64encode(pwdhash)
        return pwdhash.decode()

    def send_login_response(self, status, msg):
        data = "2:" + status + ":" + msg
        print("(L)sending on connection: ", conn)
        data = bytes(data, 'utf-8')
        self.conn.send(data)

    def send_logs_to_all_online_devices(self, logs):
        for device in clientThreads:
            if device != self and device.client_login == self.client_login:
                device.conn.send(bytes("3:" + logs, 'utf-8'))

    def store_logs(self, messageLogs):
        if self.client_login:
            self.send_logs_to_all_online_devices(messageLogs)
            with open("databases/" + self.client_login + ".json", "r+") as file:
                logs = json.load(file) + json.loads(messageLogs)
                file.seek(0)
                json.dump(logs, file)
                self.send_synchronization_response("ok", "")

    def send_synchronization_response(self, status, msg):
        data = "4:" + status + ":" + msg
        print("(L)sending on connection: ", conn)
        data = bytes(data, 'utf-8')
        self.conn.send(data)

    def synchronize(self, clientTimestamp):
        if self.client_login:
            with open("databases/" + self.client_login + ".json", "r") as file:
                allLogs = json.load(file)
                filteredLogs = [log for log in allLogs if log['timestamp'] > clientTimestamp]
                print("sending logs to: ", conn)
                print("logs: ", filteredLogs)
                if filteredLogs:
                    print("sending on connection: ", conn)
                    self.conn.send(bytes("3:" + json.dumps(filteredLogs), 'utf-8'))

def get_socket_config(file_name):
    with open(file_name, "r") as file:
        config = json.load(file)
        return config['host'], config['port']

def get_server_config(file_name):
    with open(file_name, "r") as file:
        config = json.load(file)
        return config['ssl_port'], config['smtp_server'], config['sender_email']


if __name__=='__main__':
    #password = getpass.getpass(prompt = "Type email password: ") #TODO
    keyring.set_password("server", "password", input("Type in email password: "))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server:
        host, port = get_socket_config("config.json")
        server.bind((host, port))
        clientThreads = []
        print("(L)Ready for connection")
        while True:
            server.listen()
            (conn, addr) = server.accept()
            newClient = ClientThread(addr)
            newClient.start()
            clientThreads.append(newClient)



