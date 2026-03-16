import os
import shutil
import json
import time
import socket
import hashlib
import math
import struct
from dotenv import load_dotenv
from dnslib import *
from transport import Packet, Fragmenter
from crypto_utils import HandshakeManager, Channel, decode_qname, encode_txt

class Server:
    def __init__(self):
        load_dotenv()
        self.domain = os.getenv('DOMAIN')
        self.authoritative = os.getenv('AUTHORATIVE')
        self.udp_port = int(os.getenv('UDP_PORT'))
        self.udp_ip = os.getenv('UDP_IP')
        self.ipv4 = os.getenv('IPV4')
        self.password = os.getenv('PASSWORD')
        self.active_sessions = {}

        self.upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
        if os.path.exists(self.upload_dir):
            shutil.rmtree(self.upload_dir)
        os.makedirs(self.upload_dir)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.bind((self.udp_ip, self.udp_port))
        print(f"* DNS Server listening on port {self.udp_port} for {self.domain}...")

    def get_file_metadata(self, filepath: str):
            if not os.path.exists(filepath):
                return (0, b"")
                
            file_size = os.path.getsize(filepath)
            total_chunks = math.ceil(file_size / Fragmenter.DOWNSTREAM_SIZE)
            
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                    
            return (total_chunks, sha256_hash.digest())

    def _cleanup_session(self, session_id: int):
        if session_id in self.active_sessions:
            file_handle = self.active_sessions[session_id].get("file_handle")
            if file_handle and not file_handle.closed:
                file_handle.close()
            del self.active_sessions[session_id]
            print(f"+ Closed Session {session_id}.")

    def handle_handshake(self, session_id: int, addr: tuple, raw_data: bytes):
        print(f"# Initiating Handshake for session {session_id} from {addr}!")
        hsm = HandshakeManager(self.password)

        if len(raw_data) < 74:
            print(f"- Malformed handshake length from {addr}!")
            return b""

        data, client_hmac = raw_data[:-32], raw_data[-32:]

        if not hsm.verify_hmac(data, client_hmac):
            print(f"- HMAC verification failed from {addr}!")
            return b""

        try:
            packet = Packet.unpack(data)
        except Exception as e:
            print(f"- Failed to unpack handshake: {e}")
            return b""

        if packet.session_id != session_id:
            print(f"- Session fixation attempt from {addr}! Dropping.")
            return b""

        if not packet.has_flag(Packet.SYN):
            print(f"- Handshake missing SYN flag from {addr}!")
            return b""

        session_key = hsm.obtain_session_key(packet.data)
        self.active_sessions[session_id] = {"key": session_key}
        print(f"+ Obtained Crypto Key for Session {session_id}!")

        server_pub = hsm.get_pub_bytes()
        server_packet = Packet(session_id=session_id, ack_num=0, flags=Packet.SYN | Packet.ACK, data=server_pub)
        server_bytes = server_packet.pack()
        server_hmac = hsm.gen_hmac(server_bytes)
        
        return encode_txt(server_bytes + server_hmac).encode('utf-8')

    def handle_data_phase(self, session_id: int, seq_num: int, raw_data: bytes):
        session = self.active_sessions.get(session_id)
        if not session:
            print(f"- Unauthorized packet for unknown session {session_id}!")
            return b""

        channel = Channel(session["key"])

        try:
            decrypted_data = channel.decrypt_chunk(session_id, seq_num, raw_data)
            packet = Packet.unpack(decrypted_data)
        except Exception as e:
            print(f"- Integrity failed for session {session_id}: {e}")
            return b""
        
        resp_packet= None

        #Sending Metadata
        if seq_num == 1:
            if packet.has_flag(Packet.UPL):
                if not (packet.has_flag(Packet.ACK) and packet.has_flag(Packet.DAT)):
                    print(f"- Protocol Violation: seq_num 1 UPL missing ACK or DAT flags!")
                    return b""

                filename_bytes= packet.data[:-36]
                metadata= packet.data[-36:]

                raw_filename= filename_bytes.decode('utf-8')
                total_chunks, expected_hash= struct.unpack(">I32s", metadata)

                safe_filename = os.path.basename(raw_filename)
                base_name, ext = os.path.splitext(safe_filename)
                unique_filename = f"{base_name}_{session_id}{ext}"
                filepath = os.path.join(self.upload_dir, unique_filename)

                session["filename"]= filepath
                session["action"] = "upload"
                session["total_chunks"]= total_chunks
                session["expected_hash"]= expected_hash
                session["last_written_seq"]= 1

                Fragmenter.init_empty(filepath)
                session["file_handle"] = open(filepath, "wb")

                print(f"* Session {session_id} initiated UPLOAD for: {unique_filename}")
                resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK)

            elif packet.has_flag(Packet.DWN):
                if not (packet.has_flag(Packet.ACK) and packet.has_flag(Packet.DAT)):
                    print(f"- Protocol Violation: seq_num 1 DWN missing ACK or DAT flags!")
                    return b""

                raw_filename = packet.data.decode('utf-8')

                safe_filename = os.path.basename(raw_filename)
                base_dir = os.path.dirname(os.path.abspath(__file__))
                filepath = os.path.join(base_dir, safe_filename)

                session["filename"]= filepath
                session["action"] = "download"
                print(f"* Session {session_id} requested DOWNLOAD for: {safe_filename}")

                total_chunks, raw_hash = self.get_file_metadata(filepath)
                if total_chunks == 0:
                    print(f"- Client requested non-existent file: {filepath}")
                    resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=Packet.FIN)
                else:
                    session["total_chunks"] = total_chunks
                    session["file_handle"] = open(filepath, "rb")

                    meta_payload = struct.pack(">I32s", total_chunks, raw_hash)
                    resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | Packet.DAT, data=meta_payload)
                    print(f"+ Packed Metadata: {total_chunks} chunks + 32-byte raw hash.")

            else:
                print(f"- Protocol Violation: Client sent seq_num 1 without UPL or DWN flag!")
                resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=Packet.FIN)

        # Sending Chunks
        else:
            action = session.get("action")
            file_handle = session.get("file_handle")

            if action == "upload":
                if not (packet.has_flag(Packet.ACK) and packet.has_flag(Packet.DAT) and packet.has_flag(Packet.UPL)):
                    print(f"- Protocol Violation: Upload chunk {seq_num} missing required flags!")
                    return b""

                expected_seq= session.get("last_written_seq", 1)+ 1

                if packet.data and file_handle and not file_handle.closed:
                    if seq_num== expected_seq:
                        file_handle.write(packet.data)
                        session["last_written_seq"]= seq_num
                    elif seq_num< expected_seq:
                        print(f"- DEBUG: Ignored duplicate chunk {seq_num}. Client must have missed the ACK.")
                    else:
                        print(f"- Protocol Violation: Received future chunk {seq_num} before expected {expected_seq}! Dropping.")
                        return b""

                if seq_num== session.get("total_chunks", -1)+ 1:
                    if not packet.has_flag(Packet.FIN):
                        print(f"- Protocol Violation: Final upload chunk {seq_num} is missing the FIN flag! Dropping.")
                        return b""

                    action_filename= session["filename"]
                    expected_hash= session["expected_hash"]

                    print(f"* Received final chunk for file {action_filename}. Verifying integrity...")
                    if file_handle and not file_handle.closed:
                        file_handle.close()

                    sha_hash= hashlib.sha256()
                    try:
                        with open(action_filename, "rb") as f:
                            for byte_block in iter(lambda: f.read(4096), b""):
                                sha_hash.update(byte_block)
                        actual_hash = sha_hash.digest()
                    except Exception as e:
                        print(f"- Integrity check failed (File Error): {e}")
                        actual_hash = b""

                    print(f"- DEBUG actual_hash: {actual_hash}\nexpected_hash: {expected_hash}")
                    if actual_hash== expected_hash:
                        print(f"* Upload for file {action_filename} succeded!")
                        resp_packet= Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | Packet.FIN)
                    else:
                        print(f"* Upload for file {action_filename} failed!")
                        resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=Packet.FIN)

                else:
                    if packet.has_flag(Packet.FIN):
                        print(f"- Protocol Violation: Premature FIN flag on chunk {seq_num}! Dropping.")
                        return b""

                    resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK)

            elif action == "download":
                if packet.has_flag(Packet.FIN) and packet.has_flag(Packet.ACK):
                    print(f"* Client verified download integrity and sent FIN.")
                    resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | Packet.FIN)
                else:
                    if not (packet.has_flag(Packet.ACK) and packet.has_flag(Packet.DAT) and packet.has_flag(Packet.DWN)):
                        print(f"- Protocol Violation: Client requested chunk {seq_num} without required flag!")
                        return b""
    
                    if file_handle:
                        offset = (seq_num - 2) * Fragmenter.DOWNSTREAM_SIZE 
                        file_handle.seek(offset)
                        file_data = file_handle.read(Fragmenter.DOWNSTREAM_SIZE)
                        
                        resp_flags = Packet.ACK | Packet.DAT

                        if seq_num == session.get("total_chunks", -1) + 1:
                            resp_flags |= Packet.FIN
                        
                        resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=resp_flags, data=file_data)
                    else:
                        resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=Packet.FIN)

        if packet.has_flag(Packet.FIN):
            self._cleanup_session(session_id)

        enc_resp = channel.encrypt_chunk(session_id, seq_num, resp_packet.pack())
        return encode_txt(enc_resp).encode('utf-8')

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                try:
                    req = DNSRecord.parse(data)
                except Exception as e:
                    print(f"- DEBUG Dropped garbage packet from {addr}: {e}")
                    continue

                qname = str(req.q.qname).lower().rstrip('.')
                qtype = QTYPE[req.q.qtype]

                if qname.endswith(self.domain):
                    parts = qname[:-(len(self.domain) + 1)]
                elif qname == self.authoritative:
                    parts = ""
                else:
                    print(f"- DEBUG Dropped packet. {qname} does not match {self.domain}")
                    continue
                
                print(f"Received requets {qname} of type {qtype} from {addr}")

                rep = req.reply()
                
                if qtype== "NS" and qname== self.domain:
                    rep.add_answer(RR(rname= qname, rtype= QTYPE.NS, ttl= 300, rdata= NS(self.authorative)))
                    rep.add_ar(RR(rname= self.authorative+ '.', rtype= QTYPE.A, ttl= 300, rdata= A(self.ipv4)))

                elif qtype== "A" and qname== self.authorative:
                    rep.add_answer(RR(rname= qname, rtype= QTYPE.A, ttl= 300, rdata= A(self.ipv4)))

                elif qtype== "SOA" and qname== self.domain:
                    dyn_serial= int(time.time())
                    rep.add_answer(RR(rname= qname, rtype= QTYPE.SOA, ttl= 300, 
                                    rdata= SOA(
                                        mname= self.authorative, 
                                        rname= "admin."+ self.domain,
                                        times= (
                                            dyn_serial, # Serial number
                                            3600,       # Refresh
                                            3600,       # Retry
                                            86400,      # Expire
                                            300         # Minimum TTL
                                        )
                                    )))
                
                elif qtype== "TXT" and parts:
                    labels= parts.split('.')
                    if len(labels)< 3:
                        continue
                    
                    try:
                        session_id= int(labels[-1])
                        seq_num= int(labels[-2])
                        raw_data= decode_qname("".join(labels[:-2]))
                    except Exception:
                        print(f"- DEBUG Failed to decode Base32 QNAME: {e}")
                        continue

                    if seq_num== 0:
                        txt_response= self.handle_handshake(session_id, addr, raw_data)
                    else:
                        txt_response= self.handle_data_phase(session_id, seq_num, raw_data)
                    if txt_response:
                        if len(txt_response)> 255:
                                txt_parts= [txt_response[i: i+ 255] for i in range(0, len(txt_response), 255)]
                        else:
                            txt_parts= [txt_response]
                        
                        rep.add_answer(RR(rname= req.q.qname, rtype= QTYPE.TXT, ttl=0, rdata= TXT(txt_parts)))

                    else:
                        print(f"- DEBUG txt_response was empty for seq_num {seq_num}")

                self.sock.sendto(rep.pack(), addr)

            except KeyboardInterrupt:
                print("\n* Shutting down server safely...")
                for sess_id in list(self.active_sessions.keys()):
                    self._cleanup_session(sess_id)
                self.sock.close()
                break
            except Exception as e:
                print(f"- Server loop error: {e}")

if __name__ == "__main__":
    server = Server()
    server.run()
