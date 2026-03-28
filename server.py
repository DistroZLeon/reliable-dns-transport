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
from crypto_utils import HandshakeManager, Channel, decode_qname, encode_txt, decode_txt, calc_checksum

class Server:
    def __init__(self):
        load_dotenv()
        self.domain = os.getenv('DOMAIN')
        self.authoritative = os.getenv('AUTHORATIVE')
        self.udp_port = int(os.getenv('UDP_PORT'))
        self.udp_ip = os.getenv('UDP_IP')
        self.ipv4 = os.getenv('IPV4')
        self.password = os.getenv('PASSWORD')
        self.session_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sessions.json")
        self.upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

        has_active_sessions = False
        if os.path.exists(self.session_file) and os.path.getsize(self.session_file) > 2:
            has_active_sessions = True

        if not has_active_sessions:
            if os.path.exists(self.upload_dir):
                shutil.rmtree(self.upload_dir)
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir)

        self.active_sessions = self.load_sessions()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.bind((self.udp_ip, self.udp_port))
        print(f"* DNS Server listening on port {self.udp_port} for {self.domain}...")

    def save_sessions(self):
        safe_sessions= {}
        for sess_id, data in self.active_sessions.items():
            safe_data = {
                "action": data.get("action"),
                "filename": data.get("filename"),
                "total_chunks": data.get("total_chunks"),
                "last_written_seq": data.get("last_written_seq", 0)
            }
            if "key" in data:
                safe_data["key"] = encode_txt(data["key"])
            if "expected_hash" in data:
                safe_data["expected_hash"] = encode_txt(data["expected_hash"])
                
            safe_sessions[str(sess_id)] = safe_data

        with open(self.session_file, "w") as f:
            json.dump(safe_sessions, f, indent=4)
        print("* Sessions saved to disk.")

    def load_sessions(self):
        if not os.path.exists(self.session_file):
            return {}
            
        with open(self.session_file, "r") as f:
            try:
                safe_sessions = json.load(f)
            except json.JSONDecodeError:
                return {}

        restored_sessions = {}
        for str_sess_id, data in safe_sessions.items():
            sess_id = int(str_sess_id)
            restored_data = {
                "action": data.get("action"),
                "filename": data.get("filename"),
                "total_chunks": data.get("total_chunks"),
                "last_written_seq": data.get("last_written_seq")
            }
            
            if "key" in data:
                restored_data["key"] = decode_txt(data["key"])
            if "expected_hash" in data:
                restored_data["expected_hash"] = decode_txt(data["expected_hash"])
                
            if data.get("filename") and os.path.exists(data["filename"]):
                if data.get("action") == "upload":
                    restored_data["file_handle"] = open(data["filename"], "ab")
                elif data.get("action") == "download":
                    restored_data["file_handle"] = open(data["filename"], "rb")
                    
            restored_sessions[sess_id] = restored_data
            
        print(f"* Restored {len(restored_sessions)} active sessions from disk.")
        return restored_sessions

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

    def cleanup_session(self, session_id: int):
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

        if packet.has_flag(Packet.UPL):
            resp_packet = self.process_upload(session, session_id, seq_num, packet)
        elif packet.has_flag(Packet.DWN):
            resp_packet = self.process_download(session, session_id, seq_num, packet)
        elif packet.has_flag(Packet.CMD) or packet.has_flag(Packet.RPC):
            resp_packet = self.process_command(session, session_id, seq_num, packet)
        else:
            print(f"- Protocol Violation: Packet missing routing flag (UPL/DWN/CMD)!")
            resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=Packet.FIN)

        if resp_packet.has_flag(Packet.FIN):
            self.cleanup_session(session_id)

        enc_resp = channel.encrypt_chunk(session_id, seq_num, resp_packet.pack())
        return encode_txt(enc_resp).encode('utf-8')

    def process_upload(self, session: dict, session_id: int, seq_num: int, packet: Packet):
        SERVER_FLAG = Packet.DWN 
        
        if seq_num == 1:
            if not (packet.has_flag(Packet.ACK) and packet.has_flag(Packet.DAT)):
                return Packet(session_id=session_id, ack_num=seq_num, flags=SERVER_FLAG | Packet.FIN)

            filename_bytes, metadata = packet.data[:-36], packet.data[-36:]
            total_chunks, expected_hash = struct.unpack(">I32s", metadata)
            safe_filename = os.path.basename(filename_bytes.decode('utf-8'))
            
            base_name, ext = os.path.splitext(safe_filename)
            unique_filename = f"{base_name}_{session_id}{ext}"
            filepath = os.path.join(self.upload_dir, unique_filename)

            session.update({
                "filename": filepath, "action": "upload", 
                "total_chunks": total_chunks, "expected_hash": expected_hash, "last_written_seq": 1
            })

            Fragmenter.init_empty(filepath)
            session["file_handle"] = open(filepath, "wb")
            print(f"* Session {session_id} initiated UPLOAD for: {unique_filename}")
            return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | SERVER_FLAG)

        else:
            file_handle = session.get("file_handle")
            expected_seq = session.get("last_written_seq", 1) + 1

            if packet.data and file_handle and not file_handle.closed:
                if seq_num == expected_seq:
                    file_handle.write(packet.data)
                    session["last_written_seq"] = seq_num
                elif seq_num > expected_seq:
                    return Packet(session_id=session_id, ack_num=seq_num, flags=SERVER_FLAG | Packet.FIN)

            if seq_num == session.get("total_chunks", -1) + 1:
                if not packet.has_flag(Packet.FIN): return Packet(session_id=session_id, ack_num=seq_num, flags=SERVER_FLAG | Packet.FIN)
                
                if file_handle and not file_handle.closed: file_handle.close()
                actual_hash = calc_checksum(session["filename"])
                
                if actual_hash == session["expected_hash"].hex():
                    print(f"* Upload for {session['filename']} succeeded!")
                    return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | SERVER_FLAG | Packet.FIN)
                else:
                    print(f"* Upload failed!")
                    return Packet(session_id=session_id, ack_num=seq_num, flags=SERVER_FLAG | Packet.FIN)

            return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | SERVER_FLAG)

    def process_download(self, session: dict, session_id: int, seq_num: int, packet: Packet):
        SERVER_FLAG = Packet.UPL 

        if packet.has_flag(Packet.FIN) and packet.has_flag(Packet.ACK):
            print(f"* Client verified download integrity and sent FIN.")
            return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | SERVER_FLAG | Packet.FIN)

        if seq_num == 1:
            filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.path.basename(packet.data.decode('utf-8')))
            total_chunks, raw_hash = self.get_file_metadata(filepath)
            
            if total_chunks == 0:
                return Packet(session_id=session_id, ack_num=seq_num, flags=SERVER_FLAG | Packet.FIN)

            session.update({"filename": filepath, "action": "download", "total_chunks": total_chunks})
            session["file_handle"] = open(filepath, "rb")

            meta_payload = struct.pack(">I32s", total_chunks, raw_hash)
            return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | Packet.DAT | SERVER_FLAG, data=meta_payload)

        else:
            file_handle = session.get("file_handle")
            if file_handle:
                file_handle.seek((seq_num - 2) * Fragmenter.DOWNSTREAM_SIZE)
                file_data = file_handle.read(Fragmenter.DOWNSTREAM_SIZE)
                
                resp_flags = Packet.ACK | Packet.DAT | SERVER_FLAG
                if seq_num == session.get("total_chunks", -1) + 1:
                    resp_flags |= Packet.FIN
                return Packet(session_id=session_id, ack_num=seq_num, flags=resp_flags, data=file_data)
                
            return Packet(session_id=session_id, ack_num=seq_num, flags=SERVER_FLAG | Packet.FIN)

    def process_command(self, session: dict, session_id: int, seq_num: int, packet: Packet) -> Packet:

        pass

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
                for sess_id, data in self.active_sessions.items():
                    fh = data.get("file_handle")
                    if fh and not fh.closed:
                        fh.close()
                self.save_sessions()
                self.sock.close()
                break
            except Exception as e:
                print(f"- Server loop error: {e}")

if __name__ == "__main__":
    server = Server()
    server.run()
