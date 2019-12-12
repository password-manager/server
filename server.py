import socket
import random
import string
import smtplib
import json
import hashlib
import base64
import ssl
import keyring
import os
import time
from threading import Thread
from pyisemail import is_email
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

CLEANING_PERIOD = 300

class ClientThread(Thread):
    def __init__(self, addr):
        Thread.__init__(self)
        self.addr = addr
        self.client_login = ""
        self.conn = conn
        print("(L)New connection on: ", addr)

    def run(self):
        while True:
            try:
                recv_data = self.conn.recv(2048)
                if recv_data:
                    self.manage_message(recv_data.decode("utf-8"))
                else:
                    print("(L)Closing connection to: ", addr)
                    self.conn.close()
                    exit()
            except Exception as e:
                print("(L)Exception: ", e)
                print("(L)Closing connection to: ", addr)
                exit()

    def manage_message(self, msg):
        msg_id = msg[0]
        msg = msg[2:]

        if msg_id == "0":
            self.register_client(msg)
        if msg_id == "1":
            self.verify_registration(msg)
        if msg_id == "2":
            self.login_client(msg)
        if msg_id == "3":
            self.synchronize(float(msg))
        if msg_id == "4":
            self.store_logs(msg)

    #REGISTRATION

    def register_client(self, msg):
        if self.is_client_already_registered(msg.split(":")[0]):
            self.send_registration_response("notOk", "Client with given email is already registered")
            print("(L)Client already registered")
        elif not self.verify_client_email(msg):
            self.send_registration_response("notOk", "Email address is not valid")
            print("(L)Email not valid")
        else:
            self.start_client_registration(msg)
            print("(L)Email is valid")

    def is_client_already_registered(self, login):
        return keyring.get_password("registered", login + "_hash") != None

    def verify_client_email(self, msg):
        address = msg.split(":")[0]
        try:
            return is_email(address, check_dns = True)
        except:
            print("(L)Cannot check email domain")
            return is_email(address, check_dns = False)

    def generate_verification_code(self):
        print("(L)Verification code generated")
        return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))

    def start_client_registration(self, msg):
        code = self.generate_verification_code()
        self.save_registering_client_data(msg, code)
        self.send_mail_with_verification_code(msg, code)

    def save_registering_client_data(self, msg, code):
        login, passw, salt = msg.split(":")
        keyring.set_password("registering", login + "_hash", self.generate_hash(passw, salt))
        keyring.set_password("registering", login + "_salt", salt)
        keyring.set_password("registering", login + "_code", code)
        keyring.set_password("registering", login + "_timestamp", str(time.time()))
        registering_client_logins.append(login)
        print("(L)New client added to registering clients: " + login)

    def generate_hash(self, password, salt):
        salt = bytes(salt, 'utf-8')
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000, dklen=64)
        pwdhash = base64.b64encode(pwdhash)
        print("(L)Generated hash")
        return pwdhash.decode()

    def send_mail_with_verification_code(self, msg, code):
        port, server, sender_email = get_server_config("config.json")
        receiver_email = msg.split(":")[0]
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(server, port, context=context) as server:
            server.login(sender_email, keyring.get_password("server", "password"))
            server.sendmail(sender_email, receiver_email, self.generate_email(code, sender_email, receiver_email))
        self.send_registration_response("ok", "Email with verification code sent")
        print("(L)Email with verification code sent")

    def generate_email(self, code, sender_email, receiver_email):
        message = MIMEMultipart("alternative")
        message["Subject"] = "Verification code"
        message["From"] = sender_email
        message["To"] = receiver_email
        text = """\
        Hello! 
        This email is sent to You to verify Your email address in the Secure Password Manager.
        If You haven't tried to create an account in the manager, please, ignore this email.
        Your verification code: """ + code
        email_body = MIMEText(text, "plain")
        message.attach(email_body)
        return message.as_string()

    def send_registration_response(self, status, msg):
        self.send_response("0", status, msg)

    def send_response(self, id, status, msg):
        data = bytes(id + ":" + status + ":" + msg + "\n", 'utf-8')
        self.conn.send(data)

    #REGISTARTION VERIFICATION

    def verify_registration(self, msg):
        if self.check_credentials(msg):
            self.add_new_client(msg)
            print("(L)Successful registration")
            self.send_registration_verification_response("ok", "Succesfull registration")

    def check_credentials(self, msg):
        login, password, code = msg.split(":")
        salt = keyring.get_password("registering", login + "_salt")
        if self.is_client_registering(login):
            if self.is_password_valid(login, password, salt):
                if self.is_verification_code_valid(login, code):
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

    def is_client_registering(self, login):
        return keyring.get_password("registering", login + "_hash") != None

    def is_password_valid(self, login, password, salt):
        return keyring.get_password("registering", login + "_hash") == self.generate_hash(password, salt)

    def is_verification_code_valid(self, login, code):
        return keyring.get_password("registering", login + "_code") == code

    def add_new_client(self, msg):
        login, password, _ = msg.split(":")
        hash = keyring.get_password("registering", login + "_hash")
        salt = keyring.get_password("registering", login + "_salt")
        print("(L)New client: " + login + " (" + hash + ", " + salt + ")")


        keyring.set_password("registered", login + "_hash", hash)
        keyring.set_password("registered", login + "_salt", salt)

        cipher_key = self.generate_cipher_key(login + password, salt)
        self.create_client_database(login, cipher_key)
        delete_from_registering_clients(login)

    def generate_cipher_key(self, data, salt):
        return PBKDF2(data, salt.encode(), 16, 100000)  # 128-bit key

    def create_client_database(self, login, key):
        with open("databases/" + login, 'wb') as logs:
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            logs.write(base64.b64encode(iv + cipher.encrypt(pad(str("[]").encode('utf-8'), AES.block_size))))

    def send_registration_verification_response(self, status, msg):
        self.send_response("1", status, msg)

    #LOGIN

    def login_client(self, msg):
        login, password, first_time = msg.split(":")
        if self.is_client_already_registered(login):
            salt = keyring.get_password("registered", login + "_salt")
            if keyring.get_password("registered", login + "_hash") == self.generate_hash(password, salt):
                self.client_login = login
                self.cipher_key = self.generate_cipher_key(login + password, salt)
                print("(L)Login successful")
                if first_time == '1':
                    self.send_login_response("ok", salt)
                else:
                    self.send_login_response("ok", "Login successful")
            else:
                print("(L)Login unsuccessful")
                self.send_login_response("notOk", "Login unsuccessful - wrong password")
        else:
            print("(L)Login unsuccessful")
            self.send_login_response("notOk", "Login unsuccessful - wrong email")

    def send_login_response(self, status, msg):
        self.send_response("2", status, msg)

    #SYNCHRONIZATION

    def store_logs(self, messageLogs):
        if self.client_login:
            #self.send_logs_to_all_online_devices(messageLogs) #TODO - czy chcemy tej funkcjonalności?
            logs = json.dumps(json.loads(self.get_logs()) + json.loads(messageLogs))
            self.save_logs(logs)
            self.send_synchronization_response("ok", "")
            print("(L)Storing logs")

    def send_logs_to_all_online_devices(self, logs):
        for device in client_threads:
            if device != self and device.client_login == self.client_login:
                device.conn.send(bytes("3:" + logs + "\n", 'utf-8'))
                print("(L)Sending logs to device: ", device)

    def send_synchronization_response(self, status, msg):
        self.send_response("4", status, msg)

    def synchronize(self, client_timestamp):
        if self.client_login:
            logs = json.loads(self.get_logs())
            filtered_logs = [log for log in logs if log['timestamp'] > client_timestamp]
            self.conn.send(bytes("3:" + json.dumps(filtered_logs) + "\n", 'utf-8'))
            print("(L)Sending synchronization logs: ", filtered_logs)

    def get_logs(self):
        with open("databases/" + self.client_login, 'rb') as logs:
            raw = base64.b64decode(logs.read())
            cipher = AES.new(self.cipher_key, AES.MODE_CBC, raw[:AES.block_size])
            return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf-8')

    def save_logs(self, new_data):
        with open("databases/" + self.client_login, 'wb') as logs:
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.cipher_key, AES.MODE_CBC, iv)
            logs.write(base64.b64encode(iv + cipher.encrypt(pad(str(new_data).encode('utf-8'),
                                                                AES.block_size))))

class CleaningThread(Thread):
    def run(self):
        while True:
            time.sleep(CLEANING_PERIOD)
            print("(Clean)Clients: ", registering_client_logins)
            for client in registering_client_logins:
                print("(Clean)Client: ", client)
                if time.time() - float(keyring.get_password("registering", client + "_timestamp")) > CLEANING_PERIOD:
                    delete_from_registering_clients(client)

def get_socket_config(file_name):
    with open(file_name, "r") as file:
        config = json.load(file)
        return config['host'], config['port']

def get_server_config(file_name):
    with open(file_name, "r") as file:
        config = json.load(file)
        return config['ssl_port'], config['smtp_server'], config['sender_email']

def delete_from_registering_clients(login):
    keyring.delete_password("registering", login + "_hash")
    keyring.delete_password("registering", login + "_salt")
    keyring.delete_password("registering", login + "_code")
    keyring.delete_password("registering", login + "_timestamp")

    registering_client_logins.remove(login)
    print("(L)Removing from registering clients: ", login)

def delete_client(login): #pomocnicza funkcja do testowania
    try:
        keyring.delete_password("registered", login + "_hash")
        keyring.delete_password("registered", login + "_salt")
    except:
        pass

    try:
        keyring.delete_password("registering", login + "_hash")
        keyring.delete_password("registering", login + "_salt")
        keyring.delete_password("registering", login + "_code")
        keyring.delete_password("registering", login + "_timestamp")
    except:
        pass

    try:
        os.remove("databases/" + login)
    except:
        pass
    
    try:
        registering_client_logins.remove(login)
    except:
        pass

if __name__=='__main__':
    #TODO - getpass
    #keyring.set_password("server", "password", input("Password: "))
    keyring.set_password("server", "password", "Superpassword1!")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server:
        host, port = get_socket_config("config.json")
        server.bind((host, port))
        client_threads = []
        registering_client_logins = []
        cleaning_thread = CleaningThread()
        cleaning_thread.start()
        print("(L)Ready for connection")
        while True:
            server.listen()
            server = ssl.wrap_socket(server, server_side = True, keyfile = "privateKey.key", certfile = "mycertificate.crt")
            (conn, addr) = server.accept()
            newClient = ClientThread(addr)
            newClient.start()
            client_threads.append(newClient)
