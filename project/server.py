import subprocess
import os
import signal
import shutil
import json
import time
import socket
import hashlib
import math
import struct
import threading
from worker_pool import WorkerPool
from dotenv import load_dotenv
from dnslib import *
from transport import Packet, Fragmenter
from crypto_utils import HandshakeManager, Channel, decode_qname, encode_txt, decode_txt, calc_checksum

# Main Server handling DNS/UDP multiplexing and session state
class Server:
    def __init__(self):
        load_dotenv()
        self.domain = os.getenv('DOMAIN')
        self.authorative = os.getenv('AUTHORATIVE')
        self.udp_port = int(os.getenv('UDP_PORT'))
        self.udp_ip = os.getenv('UDP_IP')
        self.ipv4 = os.getenv('IPV4')
        self.password = os.getenv('PASSWORD')
        self.session_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sessions.json")
        self.upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

        # Initialize or clean up the uploads directory based on previous state
        has_active_sessions = False
        if os.path.exists(self.session_file) and os.path.getsize(self.session_file) > 2:
            has_active_sessions = True

        if not has_active_sessions:
            if os.path.exists(self.upload_dir):
                shutil.rmtree(self.upload_dir)
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir)

        # Network and Concurrency Setup
        self.active_sessions = self.load_sessions()
        self.session_lock= threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.bind((self.udp_ip, self.udp_port))

        self.sock.settimeout(1.0)
        self.last_gc = time.time()
        self.pool= WorkerPool(target= self.handle_request)

        print(f"* DNS Server listening on port {self.udp_port} for {self.domain}...")

    # Save active sessions in .json for restart
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

    # Restore active session and related data from disk
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
                "last_written_seq": data.get("last_written_seq"),
                "last_active": time.time()
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

    # Calculate chunks and SHA-256 for integrity verification
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

    # # Free memory, close file handles, and delete temporary files
    def cleanup_session(self, session_id: int, is_abandoned: bool= False):
        if session_id in self.active_sessions:
            data= self.active_sessions[session_id]
            file_handle = self.active_sessions[session_id].get("file_handle")
            if file_handle and not file_handle.closed:
                file_handle.close()

            filename = data.get("filename")
            if filename and os.path.exists(filename):
                if is_abandoned or "cmd_out_" in filename:
                    try:
                        os.remove(filename)
                        print(f"- Deleted temporary/orphaned file: {filename}")
                    except Exception as e:
                        print(f"- Failed to delete file {filename}: {e}")
            
            del self.active_sessions[session_id]
            print(f"+ Closed Session {session_id}.")

    # Teardown idle or abandoned sessions
    def garbage_collect(self):
        current_time = time.time()
        stale_sessions = []
        
        for sid, data in list(self.active_sessions.items()):
            if current_time - data.get("last_active", current_time) > 300: 
                stale_sessions.append(sid)
                
        for sid in stale_sessions:
            print(f"- Garbage Collector: Session {sid} idle for >300s. Cleaning Up.")
            self.cleanup_session(sid, is_abandoned= True)

    # Start the ECDH Key Exchange and provide AES-GCM Session Key
    def handle_handshake(self, session_id: int, addr: tuple, raw_data: bytes):
        print(f"# Initiating Handshake for session {session_id} from {addr}!")
        
        if session_id in self.active_sessions and "handshake_resp" in self.active_sessions[session_id]:
            print(f"- DEBUG: Ignored duplicate Handshake. Resending original response.")
            return self.active_sessions[session_id]["handshake_resp"]

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
        server_pub = hsm.get_pub_bytes()
        server_packet = Packet(session_id=session_id, ack_num=0, flags=Packet.SYN | Packet.ACK, data=server_pub)
        server_bytes = server_packet.pack()
        server_hmac = hsm.gen_hmac(server_bytes)
        resp_payload = encode_txt(server_bytes + server_hmac).encode('utf-8')

        self.active_sessions[session_id] = {
            "key": session_key,
            "last_active": time.time(),
            "handshake_resp": resp_payload
        }

        print(f"+ Obtained Crypto Key for Session {session_id}!")
        return resp_payload

    # Decrypt incoming chunks and route to correct handlers
    def handle_data_phase(self, session_id: int, seq_num: int, raw_data: bytes):
        session = self.active_sessions.get(session_id)
        if not session:
            print(f"- Unauthorized packet for unknown session {session_id}!")
            return b""

        session["last_active"] = time.time()
        channel = Channel(session["key"])

        try:
            decrypted_data = channel.decrypt_chunk(session_id, seq_num, raw_data)
            packet = Packet.unpack(decrypted_data)
        except Exception as e:
            print(f"- Integrity failed for session {session_id}: {e}")
            self.cleanup_session(session_id)
            return b""

        if packet.has_flag(Packet.UPL):
            resp_packet = self.process_upload(session, session_id, seq_num, packet)
        elif packet.has_flag(Packet.DWN):
            resp_packet = self.process_download(session, session_id, seq_num, packet)
        elif packet.has_flag(Packet.CMD) or packet.has_flag(Packet.RPC):
            resp_packet = self.process_command(session, session_id, seq_num, packet)
        else:
            print(f"- Protocol Violation: Packet missing routing flag (UPL/DWN/CMD)!")
            self.cleanup_session(session_id, is_abandoned=True)
            resp_packet = Packet(session_id=session_id, ack_num=seq_num, flags=Packet.FIN)

        if resp_packet == b"":
            return b""

        enc_resp = channel.encrypt_chunk(session_id, seq_num, resp_packet.pack())
        return encode_txt(enc_resp).encode('utf-8')
    
    # Main DNS Parser. It also filters authorized traffic and extracts Base32 QNAMEs
    def handle_request(self, data, addr):
        try:
            try:
                req = DNSRecord.parse(data)
            except Exception as e:
                print(f"- DEBUG Dropped garbage packet from {addr}: {e}")
                return

            qname = str(req.q.qname).lower().rstrip('.')
            qtype = QTYPE[req.q.qtype]

            if qname.endswith(self.domain):
                parts = qname[:-(len(self.domain) + 1)]
            elif qname == self.authorative:
                parts = ""
            else:
                print(f"- DEBUG Dropped packet. {qname} does not match {self.domain}")
                return

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
                    return

                try:
                    session_id= int(labels[-1])
                    seq_num= int(labels[-2])
                    raw_data= decode_qname("".join(labels[:-2]))
                except Exception as e:
                    print(f"- DEBUG Failed to decode Base32 QNAME: {e}")
                    return
                
                with self.session_lock:
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

        except Exception as e:
            print(f"- Worker Thread Error: {e}")

    # Receive chunks from the client, write to disk, and verify SHA-256 hash
    def process_upload(self, session: dict, session_id: int, seq_num: int, packet: Packet):
        SERVER_FLAG = Packet.DWN 
        
        if seq_num == 1:
            if not (packet.has_flag(Packet.ACK) and packet.has_flag(Packet.DAT)):
                print(f"- Protocol Violation: missing ACK or DAT flags!")
                self.cleanup_session(session_id, is_abandoned=True)
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
            return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | SERVER_FLAG)

        else:
            file_handle = session.get("file_handle")
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
                    self.cleanup_session(session_id, is_abandoned=True)
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
                    self.cleanup_session(session_id)
                    return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | Packet.FIN | SERVER_FLAG)
                else:
                    print(f"* Upload for file {action_filename} failed!")
                    self.cleanup_session(session_id, is_abandoned=True)
                    return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.FIN | SERVER_FLAG)

            else:
                if packet.has_flag(Packet.FIN):
                    print(f"- Protocol Violation: Premature FIN flag on chunk {seq_num}! Dropping.")
                    self.cleanup_session(session_id, is_abandoned=True)
                    return b""

                return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | SERVER_FLAG)

    # Stream requested local file to the client
    def process_download(self, session: dict, session_id: int, seq_num: int, packet: Packet):
        SERVER_FLAG = Packet.UPL 

        if seq_num == 1:
            if not (packet.has_flag(Packet.ACK) and packet.has_flag(Packet.DAT)):
                print(f"- Protocol Violation: missing ACK or DAT flags!")
                self.cleanup_session(session_id)
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
                self.cleanup_session(session_id, is_abandoned=True)
                return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.FIN | SERVER_FLAG)
            else:
                session["total_chunks"] = total_chunks
                session["file_handle"] = open(filepath, "rb")

                meta_payload = struct.pack(">I32s", total_chunks, raw_hash)
                print(f"+ Packed Metadata: {total_chunks} chunks + 32-byte raw hash.")
                return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | Packet.DAT | SERVER_FLAG, data=meta_payload)

        else:
            if packet.has_flag(Packet.FIN) and packet.has_flag(Packet.ACK):
                print(f"* Client verified download integrity and sent FIN.")
                self.cleanup_session(session_id)
                return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | Packet.FIN | SERVER_FLAG)
            else:
                if not (packet.has_flag(Packet.ACK) and packet.has_flag(Packet.DAT) and packet.has_flag(Packet.DWN)):
                    self.cleanup_session(session_id, is_abandoned=True)
                    print(f"- Protocol Violation: Client requested chunk {seq_num} without required flags!")
                    return b""

                file_handle = session.get("file_handle")
                if file_handle:
                    offset = (seq_num - 2) * Fragmenter.DOWNSTREAM_SIZE 
                    file_handle.seek(offset)
                    file_data = file_handle.read(Fragmenter.DOWNSTREAM_SIZE)
                    
                    resp_flags = Packet.ACK | Packet.DAT | SERVER_FLAG

                    if seq_num == session.get("total_chunks", -1) + 1:
                        resp_flags |= Packet.FIN
                    
                    return Packet(session_id=session_id, ack_num=seq_num, flags=resp_flags, data=file_data)
                else:
                    self.cleanup_session(session_id)
                    return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.FIN | SERVER_FLAG)

    # Buffer command string, execute via subprocess shell, and prepare STDOUT file
    def process_command(self, session: dict, session_id: int, seq_num: int, packet: Packet):
        SERVER_FLAG = Packet.CMD 

        if session.get("action") == "download":
            print(f"- DEBUG: Resending metadata for FIN chunk {seq_num}")
            total_chunks, raw_hash = self.get_file_metadata(session["filename"])
            meta_payload = struct.pack(">I32s", total_chunks, raw_hash)
            return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | Packet.DAT | SERVER_FLAG, data=meta_payload)

        if "cmd_buffer" not in session:
            session["cmd_buffer"] = b""
            session["last_written_seq"] = 0

        expected_seq = session["last_written_seq"] + 1

        if packet.data:
            if seq_num == expected_seq:
                session["cmd_buffer"] += packet.data
                session["last_written_seq"] = seq_num
            elif seq_num < expected_seq:
                print(f"- DEBUG: Ignored duplicate CMD chunk {seq_num}.")
                if not packet.has_flag(Packet.FIN):
                    return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | SERVER_FLAG)
            else:
                print(f"- Protocol Violation: CMD chunk {seq_num}! Dropping.")
                return b""

        if packet.has_flag(Packet.FIN):
            cmd_str = session["cmd_buffer"].decode('utf-8', errors='ignore')
            print(f"* Session {session_id} Executing Remote Command: {cmd_str}")
            dangerous_substrings = ["rm -rf /", "mkfs", "dd if=", "> /dev/sda"]
            if any(danger in cmd_str for danger in dangerous_substrings):
                print(f"- SECURITY ALERT: Blocked dangerous command: {cmd_str}")
                output = b"- Error: Command blocked by Server Security Policy to prevent damage.\n" 
            else:
                try:
                    proc = subprocess.Popen(
                        cmd_str,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        start_new_session=True 
                    )
                
                    output, _ = proc.communicate(timeout=1.5)

                    if proc.returncode != 0:
                        error_header = f"- ERROR: Command failed with exit code {proc.returncode}\n".encode('utf-8')
                        output = error_header + output

                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    output, _ = proc.communicate()
                    output += b"\n- Error: Command timed out after 2 seconds!\n"
                
                except Exception as e:
                    output = f"Execution failed: {str(e)}".encode('utf-8')

            if not output:
                output = b"[Command executed successfully with no output]\n"

            out_filename = f"cmd_out_{session_id}.txt"
            out_filepath = os.path.join(self.upload_dir, out_filename)
            with open(out_filepath, "wb") as f:
                f.write(output)

            total_chunks, raw_hash = self.get_file_metadata(out_filepath)
             
            session["action"] = "download"
            session["filename"] = out_filepath
            session["total_chunks"] = total_chunks
            session["file_handle"] = open(out_filepath, "rb")

            meta_payload = struct.pack(">I32s", total_chunks, raw_hash)
            return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | Packet.DAT | SERVER_FLAG, data=meta_payload)

        else:
            return Packet(session_id=session_id, ack_num=seq_num, flags=Packet.ACK | SERVER_FLAG)

    # Main Server loop. It manages the Garbage Collector, it receives Packets and submits to thread pool
    def run(self):
        while True:
            try:
                if time.time() - getattr(self, 'last_gc', 0) > 150:
                    self.garbage_collect()
                    self.last_gc= time.time()

                try:
                    data, addr= self.sock.recvfrom(4096)
                except socket.timeout:
                    continue

                self.pool.submit(data, addr)

            except KeyboardInterrupt:
                print("\n* Shutting down server safely...")
                self.pool.shutdown()

                with self.session_lock:
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