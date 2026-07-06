import threading
import struct
import os
import json
import time
from crypto_utils import obtain_session_store_key, encode_txt, decode_txt, Channel

class AOFManager:
    def __init__(self, session_dict: dict, lock: threading.Lock, master_key: bytes, filepath: str= "aof.log"):
        self.sessions= session_dict
        self.lock= lock
        self.master_key= master_key
        self.directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aof")
        os.makedirs(self.directory, exist_ok=True)
        
        self.log_path = os.path.join(self.directory, filepath)
        self.snapshot_path = os.path.join(self.directory, "snapshot.json")

    def obtain_client_server_blobs(self, session_id: int, client_key: bytes, server_key: bytes)-> tuple[bytes, bytes]:
        key= obtain_session_store_key(session_id= session_id, master_key= self.master_key)
        enc_channel= Channel(key)
        client_iv= int.from_bytes(os.urandom(4), byteorder='big')
        server_iv= int.from_bytes(os.urandom(4), byteorder='big')

        enc_client_key= enc_channel.encrypt_chunk(session_id= session_id, seq_num= client_iv , plain_chunk= client_key)
        enc_server_key= enc_channel.encrypt_chunk(session_id= session_id, seq_num= server_iv , plain_chunk= server_key)

        client_blob= encode_txt(struct.pack(">I", client_iv) + enc_client_key)
        server_blob= encode_txt(struct.pack(">I", server_iv) + enc_server_key)
        return client_blob, server_blob
    
    def decrypt_client_server_blobs(self, session_id: int, client_blob: str, server_blob: str) -> tuple[bytes, bytes]:
        key= obtain_session_store_key(session_id= session_id, master_key= self.master_key)
        dec_channel= Channel(key)

        client= decode_txt(client_blob)
        server= decode_txt(server_blob)

        client_iv= struct.unpack(">I", client[:4])[0]
        server_iv= struct.unpack(">I", server[:4])[0]

        client_key= dec_channel.decrypt_chunk(session_id= session_id, seq_num= client_iv, cypher_chunk= client[4:])
        server_key= dec_channel.decrypt_chunk(session_id= session_id, seq_num= server_iv, cypher_chunk= server[4:])

        return client_key, server_key
    
    def trigger(self):
        threading.Thread(target= self.compaction, daemon= True).start()

    def compaction(self):
        snapshot= {}

        for session_id, data in self.sessions.items():
            client_blob, server_blob= self.obtain_client_server_blobs(session_id, data.get("client_key"), data.get("server_key")) 
            snapshot[str(session_id)]={
                "action": data.get("action"),
                "filename": data.get("filename"),
                "total_chunks": data.get("total_chunks"),
                "last_written_seq": data.get("last_written_seq", 0),
                "client_key": client_blob, 
                "server_key": server_blob,
                "expected_hash": encode_txt(data.get("expected_hash")) if data.get("expected_hash") else None
            }

        old_path= self.log_path+ ".old"
        if os.path.exists(self.log_path):
            os.replace(self.log_path, old_path)
            open(self.log_path, 'wb').close()

        tmp= self.snapshot_path+ '.tmp'
        with open(tmp, "w") as f:
            json.dump(snapshot, f)
            f.flush()
            os.dsync(f.fileno())

        os.replace(tmp, self.snapshot_path)
        if os.path.exists(old_path):
            os.remove(old_path)

        print("* AOF Compaction performed.")

    def create(self, session_id: int, session: dict):
        client_blob, server_blob= self.obtain_client_server_blobs(session_id, session.get("client_key"), session.get("server_key")) 

        data={
            "action": session.get("action"),
            "filename": session.get("filename"),
            "total_chunks": session.get("total_chunks"),
            "client_key": client_blob,
            "server_key": server_blob,
            "expected_hash": encode_txt(session.get("expected_hash")) if session.get("expected_hash") else None
        }

        payload= json.dumps(data).encode('utf-8')
        payload_len= len(payload)

        header= struct.pack(">BII", 0, session_id, payload_len)
        
        with self.lock:
            with open(self.log_path, "ab") as f:
                f.write(header+ payload)
                f.flush()
                os.fsync(f.fileno())

    def update(self, session_id: int, seq: int):
        pack= struct.pack(">BII", 1, session_id, seq)
        with self.lock:
            with open(self.log_path, "ab") as f:
                f.write(pack)
                f.flush()
                os.fsync(f.fileno())

    def delete(self, session_id: int):
        pack= struct.pack(">BI", 2, session_id)
        with self.lock:
            with open(self.log_path, "ab") as f:
                f.write(pack)
                f.flush()
                os.fsync(f.fileno())

    def replay_file(self):
        if not os.path.exists(self.log_path):
            return
        
        with open(self.log_path, "rb") as f:
            while True:
                op_bytes= f.read(1)
                if not op_bytes:
                    break
                
                code= struct.unpack(">B", op_bytes)[0]

                # Handle Session Create
                if code== 0:
                    header= f.read(8)
                    session_id, payload_len= struct.unpack(">II", header)
                    payload= f.read(payload_len)
                    data= json.loads(payload.decode('utf-8'))

                    client_key, server_key= self.decrypt_client_server_blobs(session_id, data["client_key"], data["server_key"])
                    data["client_key"]= client_key
                    data["server_key"]= server_key
                    data["last_active"]= time.time()
                        
                    if data.get("filename") and os.path.exists(data["filename"]):
                        mode= "ab" if data.get("action")== "upload" else "rb"
                        data["file_handle"]= open(data["filename"], mode)

                    if data.get("expected_hash"):
                        data["expected_hash"]= decode_txt(data["expected_hash"])
                    self.sessions[session_id]= data

                # Handle Session Update
                elif code== 1:
                    pack= f.read(8)
                    session_id, seq= struct.unpack(">II", pack)

                    if session_id in self.sessions:
                        self.sessions[session_id]["last_written_seq"]= seq

                #Handle Session Delete
                elif code== 2:
                    pack= f.read(4)
                    session_id= struct.unpack(">I", pack)[0]

                    if session_id in self.sessions:
                        del self.sessions[session_id]

        print("* AOF replayed.")