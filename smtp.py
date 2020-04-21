# -*- coding : UTF-8 -*-

import socket, sys, ssl, binascii, base64, datetime, time, os
from email import utils

def info(str):
    print("Info   : ", str)

class SMTPClient:
    BUFFER_SIZE = 1000

    def __init__(self, hostname, port = 587):
        self.hostname = hostname
        self.ipaddr = Util.ns_lookup(hostname)
        self.port = port
        self.socket = None
        self._sock = None
        self._ssl_sock = None
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
        self.no_response = False
        self.__print_status()

    def connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self.ipaddr, self.port))
        self.socket = self._sock
        self.receive()

    def start_tls(self):
        self.send("STARTTLS\n")
        self._ssl_sock = self._ssl_context.wrap_socket(
            self._sock,
            server_hostname=self.hostname
        )
        self.socket = self._ssl_sock

    def send(self, ascii_str, no_print = False):
        self.socket.send((ascii_str).encode("ascii"))
        if not no_print:
            self.__print_send_message(ascii_str)
        if (self.no_response == False):
            self.receive()

    def put(self):
        while(True):
            try:
                val = input("[+] Client : ")
                self.send(val + "\n", no_print=True)
            except KeyboardInterrupt:
                break

    def close(self):
        if isinstance(self._ssl_sock, ssl.SSLSocket):
            self._ssl_sock.close()
            info("close ssl socket")
        if isinstance(self._sock, socket.socket):
            self._sock.close()
            info("close socket")

    def receive(self):
        res = self.socket.recv(self.BUFFER_SIZE)
        self.__print_response(res)

    def __print_response(self, bin_s):
        print("[-] Server : ", bin_s.decode("ascii"), end="")

    def __print_send_message(self, s):
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
    def b64encoded_account(cls, username, password):
        str = "{name}\0{name}\0{passwd}".format(name=username, passwd=password)
        return base64.b64encode(str.encode()).decode() + "\n"

    @classmethod
    def now(cls):
        now = datetime.datetime.now()
        nowtuple = now.timetuple()
        nowtimestamp = time.mktime(nowtuple)
        rfc822 = utils.formatdate(nowtimestamp)
        return rfc822

if __name__ == "__main__":
    username = os.environ["MAIL_USERNAME"]
    password = os.environ["MAIL_PASSWORD"]
    hostname = "<...>"
    client = SMTPClient(hostname, 587)
    client.connect()
    client.start_tls()
    client.send("AUTH PLAIN\n")
    auth = Util.b64encoded_account(username=username, password=password)
    client.send(auth)
    client.send("MAIL FROM:<sample@sample.com>\n")
    client.send("RCPT TO:<sample@sample.com>\n")
    client.send("DATA\n")
    client.no_response = True
    client.send("FROM: Aki\n")
    client.send("TO: Ika\n")
    client.send("Date: {}\n".format(Util.now()))
    client.send("Subject: \(- - )")
    client.send("\n")
    client.send("Hello SMTP!\n")
    client.send(".\n")
    client.no_response = False
    client.receive()
    client.send("QUIT\n")
