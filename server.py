import os
from dotenv import load_dotenv
from dnslib import *
import cryptography
import matplotlib
import socket
import json
import time
from transport import Packet, Fragmenter
from crypto_utils import HandshakeManager, Channel, decode_qname, encode_txt

files={}
load_dotenv()

domain= os.getenv('DOMAIN')
authorative= os.getenv('AUTHORATIVE')
udp_port= int(os.getenv('UDP_PORT'))
udp_ip= os.getenv('UDP_IP')
json_file= os.getenv('JSON_FILE')
ipv4= os.getenv('IPV4')
password= os.getenv('PASSWORD')
active_sessions={}


sock= socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.bind((udp_ip, udp_port))
try:
    while(True):
        data, addr= sock.recvfrom(4096)
        try:
            req = DNSRecord.parse(data)
        except Exception as e:
            print(f"- Dropped malformed DNS packet from {addr}: {e}")
            continue
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

        elif qtype== "SOA" and qname== domain:
            dyn_serial= int(time.time())
            rep.add_answer(RR(rname= qname, rtype= QTYPE.SOA, ttl= 300, 
                              rdata= SOA(
                                  mname= authorative, 
                                  rname= "admin."+ domain,
                                  times= (
                                      dyn_serial, # Serial number
                                      3600,       # Refresh
                                      3600,       # Retry
                                      86400,      # Expire
                                      300         # Minimum TTL
                                  )
                              )))

        elif qtype== "TXT":
            if not parts:
                continue
            
            rdata=""

            parts= parts.split('.')
            if len(parts)< 3:
                print(f"- Malformed TXT query from {addr}: {qname}!")
                continue

            try:
                session_id= int(parts[-1])
                seq_num= int(parts[-2])
            except ValueError:
                print(f"- Malformed TXT query from {addr}: {qname} (bad types for sessionId and seqNum)!")
                continue

            data= "".join(parts[:-2])
            try:
                raw_data= decode_qname(data)
            except Exception as e:
                print(f"- Base32 decode failed: {e}!")
                continue

            if seq_num== 0:
                print(f"# Initiating Handshake for session {session_id}!")
                hsm= HandshakeManager(password)

                if len(raw_data)< 74:
                    print(f"- Malformed TXT query from {addr}: {qname}! (doesn't respect the pubKey+ hmac format)!")
                    continue
                data= raw_data[:-32]
                client_hmac= raw_data[-32:]

                if not hsm.verify_hmac(data, client_hmac):
                    print(f"- Wrong password from {addr}")
                    continue
                
                try:
                    packet= Packet.unpack(data)
                except Exception as e:
                    print(f"- Failed to unpack handshake: {e}")
                    continue
                
                if packet.session_id != session_id:
                    print(f"- Session fixation attempt from {addr}! Dropping packet.")
                    continue

                if not packet.has_flag(Packet.SYN):
                    print(f"- Handshake packet missing SYN flag from {addr}")
                    continue

                client_pub= packet.data
                session_key= hsm.obtain_session_key(client_pub)
                active_sessions[session_id]= {"key": session_key}

                print(f"# Obtained Crypto Key for Session {session_id}!")

                server_pub= hsm.get_pub_bytes()

                server_packet= Packet(session_id= session_id, ack_num= 0, flags= Packet.SYN| Packet.ACK, data= server_pub)
                server_bytes= server_packet.pack()

                server_hmac= hsm.gen_hmac(server_bytes)

                rdata= encode_txt(server_bytes+ server_hmac)

            else:
                if session_id not in active_sessions:
                    print(f"- Unauthorized packet for unknown session {session_id}!")
                    continue

                channel= Channel(active_sessions[session_id]["key"])

                try:
                    decrypted_data= channel.decrypt_chunk(session_id, seq_num, raw_data)

                    packet= Packet.unpack(decrypted_data)

                except Exception as e:
                    print(f"- Integrity check or unpack failed: {e}!")
                    continue

                print(f"* Decrypted packet {packet}!")

                if packet.has_flag(Packet.DAT):

                    if seq_num== 1:
                        true_filename= packet.data.decode('utf-8')
                        active_sessions[session_id]["filename"]= true_filename
                        
                        if packet.has_flag(Packet.UPL):
                            active_sessions[session_id]["action"]= "upload"
                            Fragmenter.init_empty(true_filename)
                            print(f"# Session {session_id} initiated transfer for: {true_filename}")
                        
                        elif packet.has_flag(Packet.DWN):
                            active_sessions[session_id]["action"]= "download"
                            total_chunks= Fragmenter.get_total_chunks(true_filename, Fragmenter.DOWNSTREAM_SIZE)
                            active_sessions[session_id]["total_chunks"]= total_chunks
                            print(f"# Session {session_id} initiated DOWNLOAD for: {true_filename} ({total_chunks} chunks)")
                    else:
                        action= active_sessions[session_id].get("action", "upload")
                        if action== "upload":
                            target= active_sessions[session_id].get("filename", f"upload_{session_id}.bin")
                            Fragmenter.write_chunk(target, packet.data)
                            print(f"+ Saved {len(packet.data)} bytes to {target}!")

                action= active_sessions[session_id].get("action", "upload")

                if action== "download" and seq_num> 1:
                    target= active_sessions[session_id].get("filename")
                    total_chunks= active_sessions[session_id].get("total_chunks")

                    chunk_idx= seq_num- 1

                    if chunk_idx<= total_chunks:
                        file_data= Fragmenter.read_chunk(target, chunk_idx, Fragmenter.DOWNSTREAM_SIZE)

                        rflags= Packet.ACK| Packet.DAT
                        if chunk_idx== total_chunks:
                            rflags|= Packet.FIN

                        ack_packet= Packet(session_id= session_id, ack_num= seq_num, flags= rflags, data= file_data)

                    else:
                        ack_packet= Packet(session_id= session_id, ack_num= seq_num, flags= Packet.FIN)

                else:
                    ack_packet= Packet(session_id= session_id, ack_num= seq_num, flags= Packet.ACK)

                enc_ack= channel.encrypt_chunk(session_id, seq_num, ack_packet.pack())
                rdata= encode_txt(enc_ack)

                if packet.has_flag(Packet.FIN):
                    print(f"+ Finalized transfer for Session {session_id}!")
                    del active_sessions[session_id]

            rep.add_answer(RR(rname= req.q.qname, rtype= QTYPE.TXT, ttl= 0, rdata= TXT(rdata)))

        sock.sendto(rep.pack(), addr)

except KeyboardInterrupt:
    sock.close()
    print(domain+ " "+ authorative+ " "+ str(udp_port)+ " "+ ipv4)
