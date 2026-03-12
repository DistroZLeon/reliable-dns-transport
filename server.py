import os
from dotenv import load_dotenv
from dnslib import *
import cryptography
import matplotlib
import socket
import json
import time
from transport import *
from crypto_utils import *

files={}
load_dotenv()

domain= os.getenv('DOMAIN')
authorative= os.getenv('AUTHORATIVE')
udp_port= int(os.getenv('UDP_PORT'))
udp_ip= os.getenv('UDP_IP')
json_file= os.getenv('JSON_FILE')
ipv4= os.getenv('IPV4')
password= os.getenv('PASSWORD')

sock= socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.bind((udp_ip, udp_port))
try:
    while(True):
        data, addr= sock.recvfrom(512)
        req= DNSRecord.parse(data)
        qname= str(req.q.qname)
        qtype= QTYPE[req.q.qtype]
        print(f"Received request with qname {qname} of type {qtype} from address {addr}")

        if qname.endswith("." ):
            qname= qname[:-1]
        qname= qname.lower()
        if qname.endswith(domain):
            cl= len(domain)+ 1
            parts= qname[:-cl]
        elif qname== authorative:
            parts= ""
        else:
            continue

        rep= req.reply()
        if qtype== "NS" and qname== domain:
            rep.add_answer(RR(rname= qname, rtype= QTYPE.NS, ttl= 300, rdata= NS(authorative)))
            rep.add_ar(RR(rname= authorative+ '.', rtype= QTYPE.A, ttl= 300, rdata= A(ipv4)))

        elif qtype== "A" and qname== authorative:
            rep.add_answer(RR(rname= qname, rtype= QTYPE.A, ttl= 300, rdata= A(ipv4)))

        elif qtype == "SOA" and qname == domain:
            dyn_serial= int(time.time())
            rep.add_answer(RR(rname=qname, rtype=QTYPE.SOA, ttl=300, 
                              rdata=SOA(
                                  mname=authorative, 
                                  rname="admin." + domain,
                                  times=(
                                      dyn_serial, # Serial number
                                      3600,       # Refresh
                                      3600,       # Retry
                                      86400,      # Expire
                                      300         # Minimum TTL
                                  )
                              )))

        sock.sendto(rep.pack(), addr)

except KeyboardInterrupt:
    sock.close()
    print(domain+ " "+ authorative+ " "+ str(udp_port)+ " "+ ipv4)
