# -*- coding : UTF-8 -*-

import socket, sys, ssl, base64, datetime, time, os, select
from email import utils

def info(str):
    print("Info   : ", str)

class SSLClient:
    BUFFER_SIZE = 1000

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.ipaddr = Util.ns_lookup(hostname)
        self.port = port
        self.socket = None
        self._sock = None
        self._ssl_sock = None
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
        self.__print_status()

    def connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self.ipaddr, self.port))
        self.socket = self._sock
        self.receive()

    def start_tls(self):
        self.send("STARTTLS\n")
        self.change2ssl()

    def change2ssl(self):
        self._ssl_sock = self._ssl_context.wrap_socket(
            self._sock,
            server_hostname=self.hostname
        )
        self.socket = self._ssl_sock

    def send(self, ascii_str, no_print = False, secret = False):
        self.socket.send((ascii_str).encode("ascii"))
        if not no_print:
            self.__print_send_message(ascii_str, secret = secret)
        self.receive()

    def send_multi(self):
        lines = []
        while(True):
            line = input()
            lines.append(line)
            if line == ".":
                break

        for line in lines:
            self.send(line + "\r\n")

    def talk(self):
        while(True):
            try:
                val = input("[+] Client : ")
                self.send(val + "\r\n", no_print=True)
            except KeyboardInterrupt:
                break

    def close(self):
        if isinstance(self._ssl_sock, ssl.SSLSocket):
            self._ssl_sock.close()
            info("close ssl socket")
        if isinstance(self._sock, socket.socket):
            self._sock.close()
            info("close socket")

    def receive(self, timeout = 0.1):
        while(True):
            rrdy, wrdy, xrdy = select.select([self.socket], [], [], timeout)
            if len(rrdy) == 0:
                break

            for s in rrdy:
                if not s == self.socket:
                    break
                res = s.recv(self.BUFFER_SIZE)
                multiline = len(res.splitlines()) > 1
                self.__print_response(res, multiline=multiline)

    def __print_response(self, bin_s, multiline = False):
        string = bin_s.decode()
        end = "" if string.endswith("\n") else "\n"
        if multiline:
            print("[-] Server :")
            print(string, end=end)
        else:
            print("[-] Server :", string , end=end)

    def __print_send_message(self, s, secret = False):
        if secret:
            s = "********\n"
        print("[+] Client : ", s, end="")

    def __print_status(self):
        print("\n".join([
            "hostname -> {}".format(self.hostname),
            "ip addr  -> {}".format(self.ipaddr),
            "port     -> {}".format(self.port),
        ]))

    def __del__(self):
        self.close()

class Util:
    @classmethod
    def ns_lookup(cls, domain):
        addrs = socket.getaddrinfo(domain, 80)
        if len(addrs) < 1:
            return None
        return [i[4][0] for i in addrs if len(i[4][0].split(".")) > 1][0]

    @classmethod
    def b64encoded_account(cls, username, password):
        str = "{name}\0{name}\0{passwd}".format(name=username, passwd=password)
        return base64.b64encode(str.encode()).decode() + "\r\n"

    @classmethod
    def b64decode(cls, string):
        return base64.b64decode(string).decode()

    @classmethod
    def b64encode(cls, string):
        return base64.b64encode(string.encode("utf-8")).decode()

    @classmethod
    def now(cls):
        now = datetime.datetime.now()
        nowtuple = now.timetuple()
        nowtimestamp = time.mktime(nowtuple)
        rfc822 = utils.formatdate(nowtimestamp)
        return rfc822

def smtp():
    username = os.environ["MAIL_USERNAME"]
    password = os.environ["MAIL_PASSWORD"]
    host = os.environ["MAIL_HOST"]
    to = os.environ["MAIL_TO"]
    by = os.environ["MAIL_FROM"]
    c = SSLClient(host, 587)
    c.connect()
    c.start_tls()
    c.send("AUTH PLAIN\r\n")
    auth = Util.b64encoded_account(username=username, password=password)
    c.send(auth, secret=True)
    c.send("MAIL FROM:<{}>\r\n".format(by))
    c.send("RCPT TO:<{}>\r\n".format(to))
    c.send("DATA\r\n")
    c.send("FROM: me\r\n")
    c.send("TO: you\r\n")
    c.send("Date: {}\r\n".format(Util.now()))
    c.send_multi()
    c.send("QUIT\r\n")

def imap():
    username = os.environ["MAIL_USERNAME"]
    password = os.environ["MAIL_PASSWORD"]
    host = os.environ["MAIL_HOST"]
    c = SSLClient(host, 993)
    c.connect()
    c.change2ssl()
    auth = ". login {} {}\r\n".format(username, password)
    c.send(auth, secret=True)
    c.talk()
    return c
