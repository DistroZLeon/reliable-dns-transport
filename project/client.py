import os
from dotenv import load_dotenv
from scapy.all import *
import hashlib
from transport import Packet, Fragmenter
from crypto_utils import HandshakeManager, Channel, decode_txt, encode_qname, calc_checksum

class Client:
    def __init__(self):
        load_dotenv()
        self.retries_count= 0
        self.domain= os.getenv('DOMAIN')
        self.authorative= os.getenv('AUTHORATIVE')
        self.udp_port= int(os.getenv('UDP_PORT'))
        self.dst_ip= os.getenv('DST_IP')
        self.password= os.getenv('PASSWORD')
        self.session_id= int.from_bytes(os.urandom(4), byteorder= 'big')
        self.hsm= HandshakeManager(self.password)
        self.clientChannel= None
        self.serverChannel= None
        self.upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir)

    # Calculate chunks and SHA-256 for integrity verification
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


    # Craft and send raw UDP packets, made into DNS TXT Queries
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
            return decoded_txt
        return None

    # Construct the payload wrapper
    def create_qname(self, seq_num: int, data: bytes):
        qname_array=[data[i: i+63] for i in range(0, len(data), 63)]
        qname_array. append(str(seq_num))
        qname_array.append(str(self.session_id))
        qname_array.append(self.domain)
        qname= ".".join(qname_array)
        return qname


    # Start ECDH Key Exchange and obtain AES-GCM Session Key
    def handshake(self):
        client_pub= self.hsm.get_pub_bytes()

        client_packet= Packet(session_id= self.session_id,ack_num=0, flags= Packet.SYN, data= client_pub)
        client_bytes= client_packet.pack()

        client_hmac= self.hsm.gen_hmac(client_bytes)
        data= encode_qname(client_bytes+ client_hmac)
        qname= self.create_qname(seq_num= 0, data= data)

        server_response= self.send_req(qname)

        server_response = None
        for attempt in range(3):
            server_response = self.send_req(qname)
            if server_response:
                break
            self.retries_count+= 1
            print(f"- Handshake attempt {attempt + 1} timed out. Retrying...")

        if not server_response:
            print("- FATAL: Handshake timed out after 3 attempts!")
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
            server_key, client_key= self.hsm.obtain_session_keys(server_pub)
            self.serverChannel= Channel(session_key= server_key)
            self.clientChannel= Channel(session_key= client_key)
            print(f"* Handshake completed! AES Keys are: Server = {server_key} and Client = {client_key}")
            return True
        else:
            print("- Session has not aknowledged the handshake!")
            return False  


    # Handles encryption, sending, receiving, and automatic retries
    def send_package(self, seq_num: int, flags: int, expected_resp_flag: int, data: bytes = b'', max_retries: int = 6):
        packet = Packet(session_id=self.session_id, ack_num=seq_num, flags=flags, data=data)
        encoded_payload = encode_qname(self.clientChannel.encrypt_chunk(self.session_id, seq_num, packet.pack()))
        qname = self.create_qname(seq_num, encoded_payload)

        for attempt in range(max_retries):
            response = self.send_req(qname)
            if not response:
                self.retries_count+= 1
                print(f"- Server timed out on seq {seq_num}. Retrying...")
                continue

            try:
                dec_response = self.serverChannel.decrypt_chunk(self.session_id, seq_num, response)
                resp_packet = Packet.unpack(dec_response)
            except Exception as e:
                print(f"- Decryption failed on seq {seq_num}: {e}")
                continue
            if resp_packet.ack_num == seq_num and (resp_packet.has_flag(Packet.ACK) or resp_packet.has_flag(Packet.FIN)) and resp_packet.has_flag(expected_resp_flag):
                return resp_packet
            else:
                self.retries_count+= 1
                print("- Protocol Violation: Server response missing ACK, expected response flag or wrong seq_num! Retrying...")

        print(f"- FATAL: Max retries exceeded for seq {seq_num}. Aborting.")
        return None

    # Request file from server and reconstruct it locally
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

    # Post local file to the server
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
    
    #Send shell command, wait for execution, get STDOUT
    def cmd(self, command: str):
        cmd_bytes = command.encode('utf-8')
        
        chunks = [cmd_bytes[i:i+Fragmenter.UPSTREAM_SIZE] for i in range(0, len(cmd_bytes), Fragmenter.UPSTREAM_SIZE)]
        if not chunks:
            chunks = [b""]

        total_cmd_chunks = len(chunks)
        final_resp = None

        print(f"* Uploading command payload ({total_cmd_chunks} chunks)...")
        for i, chunk in enumerate(chunks):
            seq_num = i + 1
            flags = Packet.ACK | Packet.DAT | Packet.CMD
            
            if i > 0:
                flags |= Packet.RPC
            if i == total_cmd_chunks - 1:
                flags |= Packet.FIN
            
            resp = self.send_package(seq_num, flags, Packet.CMD, chunk)
            if not resp:
                print("- Command upload failed.")
                return False
            
            if i == total_cmd_chunks - 1:
                final_resp = resp

        if not (final_resp.has_flag(Packet.DAT) and final_resp.data):
            print("- Server did not return output metadata!")
            return False

        total_chunks, expected_hash_bytes = struct.unpack(">I32s", final_resp.data)
        expected_hash = expected_hash_bytes.hex()
        print(f"+ Server executed command. Output size: {total_chunks} chunks. Expected Hash: {expected_hash[:10]}...")

        out_filepath = os.path.join(self.upload_dir, f"cmd_output_{self.session_id}.txt")
        Fragmenter.init_empty(out_filepath)

        print(f"* Downloading command output...")
        for i in range(1, total_chunks + 1):
            resp = self.send_package(i + 1, Packet.ACK | Packet.DAT | Packet.DWN, Packet.UPL)
            if not resp: return False

            if i == total_chunks and not resp.has_flag(Packet.FIN):
                print("- Protocol Violation: Server response missing FIN flag on final chunk!")
                return False

            if resp.has_flag(Packet.DAT) and resp.data:
                Fragmenter.write_chunk(out_filepath, resp.data)

        if calc_checksum(out_filepath) == expected_hash:
            print("\n================ COMMAND OUTPUT ================")
            with open(out_filepath, "r", errors="ignore") as f:
                print(f.read().strip())
            print("================================================\n")
            
            self.send_package(total_chunks + 2, Packet.ACK | Packet.FIN | Packet.DWN, Packet.UPL, max_retries=1)
            print("* Session closed cleanly.")
            if os.path.exists(out_filepath):
                os.remove(out_filepath)
                print("- Cleaned up local temporary command output.") 
            return True

        print("- Output Integrity Failed!")
        if os.path.exists(out_filepath):
            os.remove(out_filepath)
        return False

if __name__== "__main__":
    client= Client()

    if len(sys.argv)> 2:
        action= sys.argv[1]
        file= sys.argv[2]
    else:
        print("Not enough parameters!")
        exit(1)
    
    allowed_actions= ["UPL", "DWN", "CMD"]

    # Fail before handshake
    if action.upper() not in allowed_actions:
        print(f"- Invalid action '{action}'. Allowed only UPL, DWN, or CMD.")
        exit(1)
    
    if client.handshake():
        if action.upper()== "UPL":
            client.upload(file)
        elif action.upper()== "DWN":
            client.download(file)
        elif action.upper() == "CMD":
            client.cmd(" ".join(sys.argv[2:]))