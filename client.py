import os
from dotenv import load_dotenv
from scapy.all import *
import matplotlib
import socket
import time
from transport import Packet, Fragmenter
from crypto_utils import HandshakeManager, Channel, decode_txt, encode_qname
class Client:
    def __init__(self):
        load_dotenv()
        self.domain= os.getenv('DOMAIN')
        self.authorative= os.getenv('AUTHORATIVE')
        self.udp_port= int(os.getenv('UDP_PORT'))
        self.dst_ip= os.getenv('DST_IP')
        self.password= os.getenv('PASSWORD')
        self.ip= IP(dst= self.dst_ip)
        self.udp= UDP(sport= RandShort(), dport= self.udp_port)
        self.session_id= int(time.time())% 10000
        self.hsm= HandshakeManager(self.password)
        self.channel= None

    def send_req(self, qname: str):
        pck= self.ip/self.udp/DNS(rd= 1, qd= DNSQR(qname= qname, qtype= "TXT"))
        r= sr1(pck, verbose= 0, timeout= 3)
        if r and r.haslayer(DNS) and r[DNS].ancount>0:
            txt= r[DNS].an.rdata
            if isinstance(txt, list):
                txt= txt[0]
            if isinstance(txt, bytes):
                txt= txt.decode('utf-8')
            decoded_txt= decode_txt(txt)
            print(decoded_txt)
            return decoded_txt
        return None

    def handshake(self):
        client_pub= self.hsm.get_pub_bytes()

        client_packet= Packet(session_id= self.session_id,ack_num=0, flags= Packet.SYN, data= client_pub)
        client_bytes= client_packet.pack()

        client_hmac= self.hsm.gen_hmac(client_bytes)
        data= encode_qname(client_bytes+ client_hmac)
        qname_array=[data[i: i+63] for i in range(0, len(data), 63)]
        qname_array. append(str(0))
        qname_array.append(str(self.session_id))
        qname_array.append(self.domain)
        qname= ".".join(qname_array)

        server_response= self.send_req(qname)

        if not server_response:
            print("- Handshake timed out!")
            return False
        
        if len(server_response)<74:
            print(f"- Packet malformed {server_response}!") 
            return False
        
        server_bytes= server_response[:-32]
        server_hmac= server_response[-32:]

        if not self.hsm.verify_hmac(server_bytes, server_hmac):
            print(f"- Server verification failed!")
            exit(1)

        server_packet= Packet.unpack(server_bytes)
        if server_packet.session_id!= self.session_id:
            print(f"- Session fixation attempt!")
            exit(1)

        if server_packet.has_flag(Packet.SYN) and server_packet.has_flag(Packet.ACK):
            server_pub= server_packet.data
            session_key= self.hsm.obtain_session_key(server_pub)
            self.channel= Channel(session_key= session_key)
            print(f"* Handshake completed! AES Key {session_key}")
            return True
        else:
            print("- Session has not aknowledged the handshake!")
            return False  

if __name__== "__main__":
    client= Client()
    if client.handshake():
        pass