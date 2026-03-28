import struct
import os
import math

class Packet:

    # Protocol Flags
    SYN= 0x01   # Handshake
    ACK= 0x02   # Acknowledge received data
    FIN= 0x04   # End connection
    DAT= 0x08   # Contains data
    DWN= 0x10   # Download
    UPL= 0x20   # Upload
    CMD= 0x40   # Remote Command Execution
    RPC= 0x80   # Rest of Previous Command

    def __init__(self, session_id: int, ack_num: int, flags: int, data: bytes= b''):
        self.session_id = session_id
        self.ack_num = ack_num
        self.flags = flags
        self.data = data

    def pack(self)-> bytes:
        header = struct.pack(">IIB", self.session_id, self.ack_num, self.flags)
        return header + self.data

    @classmethod
    def unpack(cls, raw_data: bytes):
        if len(raw_data) < 9:
            raise ValueError("Payload is too short to contain a valid 9-byte header!")

        session_id, ack_num, flags = struct.unpack(">IIB", raw_data[:9])
        data = raw_data[9:]

        return cls(session_id, ack_num, flags, data)

    def has_flag(self, flag: int) -> bool:
        return (self.flags & flag) != 0

    def __str__(self):
        current_flags = []
        if self.has_flag(self.SYN): current_flags.append("SYN")
        if self.has_flag(self.ACK): current_flags.append("ACK")
        if self.has_flag(self.FIN): current_flags.append("FIN")
        if self.has_flag(self.DAT): current_flags.append("DAT")
        if self.has_flag(self.DWN): current_flags.append("DWN")
        if self.has_flag(self.UPL): current_flags.append("UPL")
        if self.has_flag(self.CMD): current_flags.append("CMD")
        if self.has_flag(self.RPC): current_flags.append("RPC")

        return f"[Packet | SESS: {self.session_id} | ACK: {self.ack_num} | FLAGS: {'+'.join(current_flags)} | Payload: {len(self.data)} bytes]"

class Fragmenter:
    UPSTREAM_SIZE= 110
    DOWNSTREAM_SIZE= 800

    @staticmethod
    def read_chunk(filepath: str, seq_num: int, chunk_size: int)-> bytes:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}!")

        offset= (seq_num- 1)* chunk_size

        with open(filepath, "rb") as f:
            f.seek(offset)
            data= f.read(chunk_size)
            return data

    @staticmethod
    def write_chunk(filepath: str, data: bytes):
        with open(filepath, "ab") as f:
            f.write(data)

    @staticmethod
    def get_total_chunks(filepath: str, chunk_size: int)-> int:
        if not os.path.exists(filepath):
            return 0
        file_size= os.path.getsize(filepath)
        return math.ceil(file_size/ chunk_size)

    @staticmethod
    def init_empty(filepath: str):
        with open(filepath, "wb") as f:
            pass
