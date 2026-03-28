import os
from dotenv import load_dotenv
from scapy.all import *
import matplotlib
import socket
import hashlib
import time
from transport import Packet, Fragmenter
from crypto_utils import HandshakeManager, Channel, decode_txt, encode_qname, calc_checksum

class Client:
    def __init__(self):
        load_dotenv()
        self.domain= os.getenv('DOMAIN')
        self.authorative= os.getenv('AUTHORATIVE')
        self.udp_port= int(os.getenv('UDP_PORT'))
        self.dst_ip= os.getenv('DST_IP')
        self.password= os.getenv('PASSWORD')
        self.session_id= int(time.time())% 10000
        self.hsm= HandshakeManager(self.password)
        self.channel= None
        self.upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir)

    def get_file_metadata(self, filepath: str):
            if not os.path.exists(filepath):
                return (0, b"")
                
            file_size = os.path.getsize(filepath)
            total_chunks = math.ceil(file_size / Fragmenter.UPSTREAM_SIZE)
            
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                    
            return (total_chunks, sha256_hash.digest())

    def send_req(self, qname: str):
        pck= IP(dst= self.dst_ip)/UDP(sport= RandShort(), dport= self.udp_port)/DNS(
            id=RandShort(), 
            rd= 1, 
            qd= DNSQR(qname= qname, qtype= "TXT"),
            ar= DNSRROPT(rclass=4096)
        )
        r= sr1(pck, verbose= 0, timeout= 3, iface= "wlp2s0")
        if r and r.haslayer(DNS) and r[DNS].ancount>0:
            txt= r[DNS].an.rdata
            if isinstance(txt, list):
                txt= b"".join(txt)
        
            if isinstance(txt, bytes):
                txt= txt.decode('utf-8')
            decoded_txt= decode_txt(txt)
            print(decoded_txt)
            return decoded_txt
        return None

    def create_qname(self, seq_num: int, data: bytes):
        qname_array=[data[i: i+63] for i in range(0, len(data), 63)]
        qname_array. append(str(seq_num))
        qname_array.append(str(self.session_id))
        qname_array.append(self.domain)
        qname= ".".join(qname_array)
        return qname

    def handshake(self):
        client_pub= self.hsm.get_pub_bytes()

        client_packet= Packet(session_id= self.session_id,ack_num=0, flags= Packet.SYN, data= client_pub)
        client_bytes= client_packet.pack()

        client_hmac= self.hsm.gen_hmac(client_bytes)
        data= encode_qname(client_bytes+ client_hmac)
        qname= self.create_qname(seq_num= 0, data= data)

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

    def send_package(self, seq_num: int, flags: int, expected_resp_flag: int, data: bytes = b'', max_retries: int = 3):
        packet = Packet(session_id=self.session_id, ack_num=seq_num, flags=flags, data=data)
        encoded_payload = encode_qname(self.channel.encrypt_chunk(self.session_id, seq_num, packet.pack()))
        qname = self.create_qname(seq_num, encoded_payload)

        for attempt in range(max_retries):
            response = self.send_req(qname)
            if not response:
                print(f"- Server timed out on seq {seq_num}. Retrying...")
                continue

            try:
                dec_response = self.channel.decrypt_chunk(self.session_id, seq_num, response)
                resp_packet = Packet.unpack(dec_response)
            except Exception as e:
                print(f"- Decryption failed on seq {seq_num}: {e}")
                continue
            if resp_packet.ack_num == seq_num and (resp_packet.has_flag(Packet.ACK) or resp_packet.has_flag(Packet.FIN)) and resp_packet.has_flag(expected_resp_flag):
                return resp_packet
            else:
                print("- Protocol Violation: Server response missing ACK, expected response flag or wrong seq_num! Retrying...")

        print(f"- FATAL: Max retries exceeded for seq {seq_num}. Aborting.")
        return None

    def download(self, filename: str):
        safe_filename = os.path.basename(filename)
        filepath = os.path.join(self.upload_dir, f"{os.path.splitext(safe_filename)[0]}_{self.session_id}{os.path.splitext(safe_filename)[1]}")

        resp = self.send_package(1, Packet.ACK | Packet.DAT | Packet.DWN, Packet.UPL,filename.encode('utf-8'))
        if not resp: return False
        
        if resp.has_flag(Packet.FIN):
            print(f"- Server reported file not found: {filename}")
            return False

        total_chunks, expected_hash_bytes = struct.unpack(">I32s", resp.data)
        expected_hash = expected_hash_bytes.hex()
        print(f"+ Server confirmed: {total_chunks} chunks. Expected Hash: {expected_hash[:10]}...")
        Fragmenter.init_empty(filepath)

        for i in range(1, total_chunks + 1):
            resp = self.send_package(i + 1, Packet.ACK | Packet.DAT | Packet.DWN, Packet.UPL)
            if not resp: return False

            if i == total_chunks and not resp.has_flag(Packet.FIN):
                print("- Protocol Violation: Server response missing FIN flag on final chunk!")
                return False
            
            if i != total_chunks and resp.has_flag(Packet.FIN):
                print(f"- Server reported failure when sending chunk {i}!")
                return False

            if resp.has_flag(Packet.DAT) and resp.data:
                Fragmenter.write_chunk(filepath, resp.data)
                print(f"+ Downloaded chunk {i}/{total_chunks}")

        print("* Verifying SHA-256 integrity...")
        if calc_checksum(filepath) == expected_hash:
            print("+ Integrity Passed!")
            self.send_package(total_chunks + 2, Packet.ACK| Packet.FIN| Packet.DWN, Packet.UPL,max_retries=1)
            print("* Session closed cleanly.")
            return True
            
        print("- Integrity Failed!")
        return False

    def upload(self, filename: str):
        safe_filename = os.path.basename(filename)
        filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), safe_filename)

        total_chunks, raw_hash = self.get_file_metadata(filepath)
        if total_chunks == 0:
            print(f"- File not found: {filepath}")
            return False

        meta_payload = safe_filename.encode('utf-8') + struct.pack(">I32s", total_chunks, raw_hash)
        resp = self.send_package(1, Packet.ACK | Packet.DAT | Packet.UPL, Packet.DWN, meta_payload)
        if not resp: return False

        for i in range(1, total_chunks + 1):
            flags = Packet.ACK | Packet.DAT | Packet.UPL
            if i == total_chunks: flags |= Packet.FIN
            
            chunk_data = Fragmenter.read_chunk(filepath, i, Fragmenter.UPSTREAM_SIZE)
            resp = self.send_package(i + 1, flags, Packet.DWN, chunk_data)
            if not resp: return False

            if i == total_chunks and not resp.has_flag(Packet.FIN):
                print("- Protocol Violation: Last Server response is missing FIN flag!")
                return False
            
            if i != total_chunks and resp.has_flag(Packet.FIN):
                print(f"- Server reported failure when receiving chunk {i}!")
                return False

            print(f"+ Uploaded chunk {i}/{total_chunks}")

        print(f"* Upload for file {filepath} completed and verified by server.")
        return True

if __name__== "__main__":
    client= Client()

    if len(sys.argv)> 2:
        action= sys.argv[1]
        file= sys.argv[2]
    else:
        print("Not enough parameters!")
        exit(1)

    if client.handshake():
        if action.upper()== "UPL":
            client.upload(file)
        elif action.upper()== "DWN":
            client.download(file)