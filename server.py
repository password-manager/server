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
#from Crypto.Protocol.KDF import PBKDF2


class ClientThread(Thread):
    def __init__(self, addr):
        Thread.__init__(self)
        self.addr = addr
        self.client_login = ""
        self.conn = conn
        print("(L)New connection on: ", addr)

    def run(self):
        while True:
            recv_data = self.conn.recv(2048)
            if recv_data:
                self.manage_message(recv_data)
            else:
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

    #REGISTRATION

    def register_client(self, msg):
        if self.is_client_already_registered(msg):
            self.send_registration_response("notOk", "Client with given email is already registered")
            print("(L)Client already registered")
        elif not self.verify_client_email(msg):
            self.send_registration_response("notOk", "Email address is not valid")
            print("(L)Email not valid")
        else:
            print("(L)Email is valid")
            code = self.generate_verification_code()
            self.save_client_data(msg, code)
            self.send_mail_with_verification_code(msg, code)
            self.send_registration_response("ok", "Email with verification code sent")

    def is_client_already_registered(self, msg):
        if keyring.get_password("registered", msg.split(":")[0] + "_hash") == None:
            return True
        return False

    def verify_client_email(self, msg):
        address, _, _ = msg.split(":")
        return is_email(address, check_dns=False) #TODO

    def generate_verification_code(self):
        print("(L)Generated code")
        return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))

    def save_client_data(self, msg, code):
        #TODO - check if client with given email is on the registrating list
        login, passw, salt = msg.split(":")
        keyring.set_password("registering", login + "_hash", self.generate_hash(passw, salt))
        keyring.set_password("registering", login + "_salt", salt)
        keyring.set_password("registering", login + "_code", code)
        print("(L)New client added to registering clients: " + login)

    def generate_hash(self, password, salt):
        #TODO -> verifyPassword
        #TODO - ??
        salt = bytes(salt, 'utf-8')
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000, dklen=64)
        pwdhash = base64.b64encode(pwdhash)
        print("(L)Generated hash")
        return pwdhash.decode()

    def send_mail_with_verification_code(self, msg, code):
        #TODO - nicer looking email
        #TODO - ??
        port, server, mail = get_server_config("config.json")
        receiver_email = msg.split(":")[0]
        #message = EmailMessage()
        #message['Subject'] = f'Verification code from AGH Password Manager'
        message = "Your verification code: " + code
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(server, port, context = context) as server:
            server.login(mail, keyring.get_password("server", "password"))
            server.sendmail(mail, receiver_email, message)
        print("(L)Email with verification code sent")

    def send_registration_response(self, status, msg):
        #TODO - refactoring
        data = "0:" + status + ":" + msg
        data = bytes(data, 'utf-8')
        self.conn.send(data)


    #REGISTARTION VERIFICATION

    def verify_registration(self, msg):
        #todo - sprawdzanie hasła
        if self.check_verification_code(msg):
            self.add_new_client(msg)
            print("(L)Successful registration")
            self.send_registration_verification_response("ok", "Succesfull registration")

    def check_verification_code(self, msg):
        login, passw, code = msg.split(":")
        salt = keyring.get_password("registering", login + "_salt")
        if keyring.get_password("registering", login + "_hash"):
            if keyring.get_password("registering", login + "_hash") == self.generate_hash(passw, salt):
                if keyring.get_password("registering", login + "_code") == code:
                    print("(L)Verification code correct")
                    return True
                else:
                    self.send_registration_verification_response("notOk", "Verification code incorrect")
                    print("(L)Verification code incorrect")
            else:
                self.send_registration_verification_response("notOk", "Password incorrect")
                print("(L)Password incorrect")
        else:
            self.send_registration_verification_response("notOk", "Client doesn't exist")
            print("(L)Client login incorrect")


        return False

    def add_new_client(self, msg):
        #TODO - delete client from registering clients
        #TODO - cipher key
        login, _, _ = msg.split(":")

        hash = keyring.get_password("registering", login + "_hash")
        salt = keyring.get_password("registering", login + "_salt")

        keyring.delete_password("registering", login + "_hash")
        keyring.delete_password("registering", login + "_salt")
        keyring.delete_password("registering", login + "_code")

        print("(L)New client: " + login + " (" + hash + ", " + salt + ")")

        keyring.set_password("registered", login + "_hash", hash)
        keyring.set_password("registered", login + "_salt", salt)

        #cipher_key = PBKDF2(self.client_login + hash, salt.encode(), 16, 100000)  # 128-bit key
        #keyring.set_password("registered", login + "_cipher", cipher_key)

        with open("databases/" + login + ".json", "w+") as file:
            file.write("[]")

    def send_registration_verification_response(self, status, msg):
        #TODO - refactoring
        data = "1:" + status + ":" + msg
        data = bytes(data, 'utf-8')
        self.conn.send(data)


    #LOGIN

    def login_client(self, msg):
        #TODO - konkretne kozy
        #TODO - first time - sending salt
        login, password, first_time = msg.split(":")
        if self.verify_password(login, password):
            print("(L)Login successful")
            if first_time == 1:
                self.send_login_response("ok", keyring.get_password("registered", login + "_salt"))
            else:
                self.send_login_response("ok", "Login successful")
            self.client_login = login
        else:
            print("(L)Login unsuccessful")
            self.send_login_response("notOk", "Login unsuccessful - wrong password")

    def verify_password(self, login, password):
        #TODO - refactoring
        #TODO - does he exist?
        stored_hash = keyring.get_password("registered", login + "_hash")
        stored_salt = keyring.get_password("registered", login + "_salt")

        if stored_hash and stored_hash == self.generate_hash(password, stored_salt):
            print("(L)Password correct")
            return True
        return False

    def send_login_response(self, status, msg):
        #TODO - refactoring
        data = "2:" + status + ":" + msg
        data = bytes(data, 'utf-8')
        self.conn.send(data)


    #SYNCHRONIZATION

    def store_logs(self, messageLogs):
        #TODO - ciphering file
        #TODO - refactoring
        if self.client_login:
            self.send_logs_to_all_online_devices(messageLogs)
            with open("databases/" + self.client_login + ".json", "r+") as file:
                logs = json.load(file) + json.loads(messageLogs)
                file.seek(0)
                print("(L)Storing logs: ", logs)
                json.dump(logs, file)
                self.send_synchronization_response("ok", "")

    def send_logs_to_all_online_devices(self, logs):
        for device in clientThreads:
            if device != self and device.client_login == self.client_login:
                device.conn.send(bytes("3:" + logs, 'utf-8'))
                print("(L)Sending logs to device: ", device)

    def send_synchronization_response(self, status, msg):
        #TODO - refactoring
        data = "4:" + status + ":" + msg
        data = bytes(data, 'utf-8')
        self.conn.send(data)


    def synchronize(self, clientTimestamp):
        #TODO - ciphering file
        #TODO - refactoring
        if self.client_login:
            with open("databases/" + self.client_login + ".json", "r") as file:
                allLogs = json.load(file)
                filteredLogs = [log for log in allLogs if log['timestamp'] > clientTimestamp]
                self.conn.send(bytes("3:" + json.dumps(filteredLogs), 'utf-8'))
                print("(L)Sending synchronization logs: ", filteredLogs)


def get_socket_config(file_name):
    with open(file_name, "r") as file:
        config = json.load(file)
        return config['host'], config['port']

def get_server_config(file_name):
    with open(file_name, "r") as file:
        config = json.load(file)
        return config['ssl_port'], config['smtp_server'], config['sender_email']


if __name__=='__main__':
    try:
        keyring.delete_password("registered", "klaudia.ma.garnek@gmail.com_hash")
        keyring.delete_password("registered", "klaudia.ma.garnek@gmail.com_salt")
        #keyring.delete_password("registered", "klaudia.ma.garnek@gmail.com_cipher")
        keyring.delete_password("registering", "klaudia.ma.garnek@gmail.com_hash")
        keyring.delete_password("registering", "klaudia.ma.garnek@gmail.com_salt")
        keyring.delete_password("registering", "klaudia.ma.garnek@gmail.com_code")

        keyring.delete_password("registered", "klaudia.ma.garnek@onet.pl_hash")
        keyring.delete_password("registered", "klaudia.ma.garnek@onet.pl_salt")
        #keyring.delete_password("registered", "klaudia.ma.garnek@onet.pl_cipher")
        keyring.delete_password("registering", "klaudia.ma.garnek@onet.pl_hash")
        keyring.delete_password("registering", "klaudia.ma.garnek@onet.pl_salt")
        keyring.delete_password("registering", "klaudia.ma.garnek@onet.pl_code")

    except:
        pass

    #TODO - getpass
    #TODO - TLS
    #keyring.set_password("server", "password", input("Type in email password: "))
    keyring.set_password("server", "password", "strongestPasswordEver")

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
