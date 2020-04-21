# -*- coding : UTF-8 -*-

import socket, sys, ssl, binascii, base64, datetime, time, os, select
from email import utils

def info(str):
    print("Info   : ", str)

class IMAPSClient:
    BUFFER_SIZE = 1000

    def __init__(self, hostname, port = 993):
        self.hostname = hostname
        self.ipaddr = Util.ns_lookup(hostname)
        self.port = port
        self.socket = None
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
        self.__print_status()

    def connect(self):
        self.socket = self._ssl_context.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=self.hostname
        )
        self.socket.connect((self.ipaddr, self.port))
        self.receive()

    def send(self, ascii_str, no_print = False, secret = False):
        self.socket.send((ascii_str).encode())
        if not no_print:
            self.__print_send_message(ascii_str, secret = secret)
        self.receive()

    def talk(self):
        while(True):
            try:
                val = input("[+] Client : ")
                if val == "":
                    self.receive()
                else:
                    self.send(val + "\r\n", no_print=True)
            except KeyboardInterrupt:
                break

    def close(self):
        if isinstance(self.socket, ssl.SSLSocket):
            self.socket.close()
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
        return addrs[0][4][0]

    @classmethod
    def now(cls):
        now = datetime.datetime.now()
        nowtuple = now.timetuple()
        nowtimestamp = time.mktime(nowtuple)
        rfc822 = utils.formatdate(nowtimestamp)
        return rfc822

    @classmethod
    def b64decode(cls, string):
        return base64.b64decode(string).decode()

if __name__ == "__main__":
    username = os.environ["MAIL_USERNAME"]
    password = os.environ["MAIL_PASSWORD"]
    hostname = "<...>"
    client = IMAPSClient(hostname)
    client.connect()
    auth = ". login {} {}\r\n".format(username, password)
    client.send(auth, secret=True)
    client.send('. list "" "%"\r\n')
    client.send('. select inbox\r\n')
    client.send('. fetch 12 bodystructure\r\n')
    client.send('. fetch 12 envelope\r\n')
    client.send('. search (text "aki")\r\n')
    time.sleep(3)
    client.receive()
    client.send('. fetch 12 body[0]\r\n')
    client.send('. fetch 12 body[1]\r\n')
    client.send('. fetch 12 body[1]\r\n')
    client.send('. fetch 261 body[1]\r\n')
    client.send('. fetch 261 body[1]\r\n')
