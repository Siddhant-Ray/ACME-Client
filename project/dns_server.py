#!/usr/bin/env python

"Code referenced from dnslib documentation"

import argparse
import datetime
import sys
import time
import threading
import traceback
import socket
import struct

import binascii,socket,struct,threading,time

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

try:
    from dnslib.server import DNSServer, DNSLogger, UDPServer
    from dnslib.dns import RR, DNSRecord

except ImportError:
    print("Missing dependency dnslib, Please install it with `pip`.")
    sys.exit(2)

class TCPServer(socketserver.TCPServer,socketserver.ThreadingMixIn,object):
    def __init__(self, server_address, handler):
        self.allow_reuse_address = True
        self.daemon_threads = True
        if server_address[0] != '' and ':' in server_address[0]:
            self.address_family = socket.AF_INET6
        super(TCPServer,self).__init__(server_address, handler)

class UDPServer(socketserver.UDPServer,socketserver.ThreadingMixIn,object):
    def __init__(self, server_address, handler):
        self.allow_reuse_address = True
        self.daemon_threads = True
        if server_address[0] != '' and ':' in server_address[0]:
            self.address_family = socket.AF_INET6
        super(UDPServer,self).__init__(server_address, handler)

class TestResolver:

    def __init__(self, domain, record):

        self.domain = domain
        self.record  = record

    def resolve(self, request, handler):
        print(self.domain)
        print(self.record)

        #import ipdb;
        #ipdb.set_trace()

        reply = request.reply()
        reply.add_answer(*RR.fromZone(str(self.domain)+ " 60 A " + str(self.record)))
        return reply

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Run the DNS')
    parser.add_argument("-d","--dir", help='pass the domain')
    parser.add_argument("-r","--record", help='IP record for resolving')
    args = parser.parse_args()
    
    resolver = TestResolver(args.dir, args.record)

    logger = DNSLogger(prefix=False)
    server = DNSServer(resolver, port = 10053, address="localhost", logger=logger, server = UDPServer)
    server.start_thread()

    q = DNSRecord.question("https://example.com/dir")
    a = q.send("localhost", 10053, tcp=False)

    print(DNSRecord.parse(a))





