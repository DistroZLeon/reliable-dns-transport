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

    def download(self, filename: str):
        seq_num= 1
        first_packet= Packet(session_id= self.session_id, ack_num= seq_num, flags= Packet.ACK| Packet.DAT| Packet.DWN, data= filename.encode('utf-8'))
        first_bytes= first_packet.pack()
        data= encode_qname(self.channel.encrypt_chunk(session_id= self.session_id, seq_num= seq_num, plain_chunk= first_bytes))
        first_qname= self.create_qname(seq_num= seq_num, data= data)
        first_response= self.send_req(first_qname)

        if not first_response:
                print(f"- Server timed out on getting metadata for file {filename}.")
                return False
        
        try:
            dec_response = self.channel.decrypt_chunk(self.session_id, seq_num, first_response)
            first_packet = Packet.unpack(dec_response)
        except Exception as e:
            print(f"- Decryption or unpack failed: {e}")
            return False

        if first_packet.has_flag(Packet.FIN):
            print(f"- Server reported file not found: {filename}")
            return False

        if not (first_packet.ack_num== 1 and first_packet.has_flag(Packet.ACK)):
            print(f"- Protocol Violation: Server response missing ACK or wrong seq_num!")
            return False
        try:
            total_chunks, expected_hash = struct.unpack(">I32s", first_packet.data)
        except Exception as e:
            print(f"- Failed to parse metadata payload: {e}")
            return False
        expected_hash= expected_hash.hex()
        print(f"+ Server confirmed: {total_chunks} chunks. Expected Hash: {expected_hash[:10]}...")
        Fragmenter.init_empty("result.txt")

        for i in range(1, total_chunks+ 1):
            max_retries= 3
            chunk_success= False
            packet= Packet(session_id= self.session_id, ack_num= i+ 1, flags= Packet.ACK| Packet.DAT| Packet.DWN, data= filename.encode('utf-8'))
            packet_bytes= packet.pack()
            data= encode_qname(self.channel.encrypt_chunk(session_id= self.session_id, seq_num= i+ 1, plain_chunk= packet_bytes))
            qname= self.create_qname(seq_num= i+ 1, data= data)
            for attempt in range(max_retries):
                response= self.send_req(qname)

                if not response:
                    print(f"- Server timed out on chunk {i}/{total_chunks}.")
                    continue

                try:
                    dec_chunk_response = self.channel.decrypt_chunk(self.session_id, i+ 1, response)
                    chunk_packet = Packet.unpack(dec_chunk_response)
                except Exception as e:
                    print(f"- Decryption failed on chunk {i}: {e}")
                    continue

                if chunk_packet.ack_num == i+ 1 and chunk_packet.has_flag(Packet.ACK):
                    if i == total_chunks and not chunk_packet.has_flag(Packet.FIN):
                        print(f"- Protocol Violation: Server response missing FIN flag on final chunk! Retrying...")
                        continue

                    if chunk_packet.has_flag(Packet.DAT) and chunk_packet.data:
                        Fragmenter.write_chunk("result.txt", chunk_packet.data)
                        print(f"+ Downloaded chunk {i}/{total_chunks}")
                        chunk_success = True
                        break
                else:
                    print(f"- Protocol Violation: Server response missing ACK or wrong seq_num! Retrying...")
            
            if not chunk_success:
                print(f"- FATAL: Max retries exceeded for chunk {i}. Aborting transfer.")
                return False
            
        print("* Verifying SHA-256 integrity")
        hash_hex= calc_checksum("result.txt")

        if hash_hex== expected_hash:
            print(f"+ Integrity Passed!")
            fin_seq = total_chunks + 2
            fin_packet = Packet(session_id=self.session_id, ack_num=fin_seq, flags=Packet.ACK | Packet.FIN)
            fin_bytes = fin_packet.pack()
            data = encode_qname(self.channel.encrypt_chunk(session_id=self.session_id, seq_num=fin_seq, plain_chunk=fin_bytes))
            qname = self.create_qname(seq_num=fin_seq, data=data)
            
            self.send_req(qname)
            print("* Session closed cleanly.")
            return True
        else:
            print("- Integrity Failed!")
            print(f"  Expected: {expected_hash}")
            print(f"  Actual:   {hash_hex}")
            return False

    def upload(self, filename: str):
        seq_num= 1

        safe_filename = os.path.basename(filename)
        base_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(base_dir, safe_filename)

        total_chunks, raw_hash= self.get_file_metadata(filepath)
        if total_chunks== 0:
            print(f"- Received as parameter non-existing file: {filepath}")
            return False
        
        meta_payload= struct.pack(">I32s", total_chunks, raw_hash)

        first_packet= Packet(session_id= self.session_id, ack_num= seq_num, flags= Packet.ACK| Packet.DAT| Packet.UPL, data= safe_filename.encode('utf-8')+ meta_payload)
        print(first_packet)
        first_bytes= first_packet.pack()
        data= encode_qname(self.channel.encrypt_chunk(session_id= self.session_id, seq_num= seq_num, plain_chunk= first_bytes))
        first_qname= self.create_qname(seq_num= seq_num, data= data)
        first_response= self.send_req(first_qname)

        if not first_response:
                print(f"- Server timed out on getting metadata for file {filename}.")
                return False
        
        try:
            dec_response = self.channel.decrypt_chunk(self.session_id, seq_num, first_response)
            first_packet = Packet.unpack(dec_response)
        except Exception as e:
            print(f"- Decryption or unpack failed: {e}")
            return False
        
        if not (first_packet.ack_num== 1 and first_packet.has_flag(Packet.ACK)):
            print(f"- Protocol Violation: Server response missing ACK or wrong seq_num!")
            return False

        print(first_packet)

        for i in range(1, total_chunks+ 1):
            max_retries= 3
            chunk_success= False
            current_flags = Packet.ACK | Packet.DAT | Packet.UPL
            if i == total_chunks:
                current_flags |= Packet.FIN
            packet= Packet(
                session_id= self.session_id, 
                ack_num= i+ 1, 
                flags= current_flags, 
                data= Fragmenter.read_chunk(filepath= filepath, seq_num= i, chunk_size= Fragmenter.UPSTREAM_SIZE)
            )
            packet_bytes= packet.pack()
            data= encode_qname(self.channel.encrypt_chunk(session_id= self.session_id, seq_num= i+ 1, plain_chunk= packet_bytes))
            qname= self.create_qname(seq_num= i+ 1, data= data)
            for attempt in range(max_retries):
                response= self.send_req(qname)

                if not response:
                    print(f"- Server timed out on chunk {i}/{total_chunks}.")
                    continue
                

                try:
                    dec_chunk_response = self.channel.decrypt_chunk(self.session_id, i+ 1, response)
                    chunk_packet = Packet.unpack(dec_chunk_response)
                    print(chunk_packet)
                except Exception as e:
                    print(f"- Decryption failed on chunk {i}: {e}")
                    continue

                if chunk_packet.ack_num == i+ 1 and chunk_packet.has_flag(Packet.ACK):
                    if chunk_packet.ack_num== total_chunks+ 1:
                        if chunk_packet.has_flag(Packet.FIN):
                            chunk_success = True
                            print(f"* Upload for file {filepath} completed")
                            break
                        else:
                            print(f"- Protocol Violation: Last Server response is missing FIN flag!")
                            return False
                    else:
                        print(f"+ Uploaded chunk {i}/{total_chunks}")
                        chunk_success = True
                        break
                else:
                    print(f"- Protocol Violation: Server response missing ACK or wrong seq_num! Retrying...")
                

            if not chunk_success:
                print(f"- FATAL: Max retries exceeded for chunk {i}. Aborting transfer.")
                return False

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