import struct
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature

# DNS Transport Utilities
def encode_qname(data: bytes)-> str:
    return base64.b32encode(data).decode('utf-8').rstrip('=')

def decode_qname(b32_str: str)-> bytes:
    rest= len(b32_str)% 8
    padding= ""
    if rest:
        padding= '='* (8- rest)
    return base64.b32decode((b32_str+ padding).encode('utf-8'), casefold= True)

def encode_txt(data: bytes)-> str:
    return base64.b64encode(data).decode('utf-8')

def decode_txt(b64_str: str)-> bytes:
    return base64.b64decode(b64_str.encode('utf-8'))

# File Integrity Utilities
def calc_checksum(filepath: str)-> str:
    sha256_hash= hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Crypto Session Managers
class HandshakeManager:
    def __init__(self, password: str):
        self.psk= password.encode('utf-8')

        self.priv_key= ec.generate_private_key(ec.SECP256R1())
        self.pub_key= self.priv_key.public_key()

    def get_pub_bytes(self)-> bytes:
        return self.pub_key.public_bytes(
                encoding= serialization.Encoding.X962,
                format= serialization.PublicFormat.CompressedPoint
            )

    def gen_hmac(self, data: bytes)-> bytes:
        h= hmac.HMAC(self.psk, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def verify_hmac(self, data: bytes, signature: bytes)-> bool:
        h= hmac.HMAC(self.psk, hashes.SHA256())
        h.update(data)
        try:
            h.verify(signature)
            return True
        except InvalidSignature:
            return False

    def obtain_session_keys(self, peer_pub_bytes: bytes)-> tuple[bytes, bytes]:
        peer_pub_key= ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), peer_pub_bytes
            )
        shared= self.priv_key.exchange(ec.ECDH(), peer_pub_key)

        key_material= HKDF(
                algorithm= hashes.SHA256(),
                length= 64,
                salt= None,
                info= b'session-encryption-keys'
            ).derive(shared)
        
        server_key= key_material[:32] 
        client_key= key_material[32:]

        return server_key, client_key

class Channel:
    def __init__(self, session_key: bytes):
        self.aesgcm= AESGCM(session_key)

    def derive_iv(self, session_id: int, seq_num: int)-> bytes:
        return struct.pack(">II4x", session_id, seq_num)

    def encrypt_chunk(self, session_id: int, seq_num: int, plain_chunk: bytes)-> bytes:
        iv= self.derive_iv(session_id, seq_num)
        meta_data= struct.pack(">II", session_id, seq_num)
        return self.aesgcm.encrypt(iv, plain_chunk, meta_data)

    def decrypt_chunk(self, session_id: int, seq_num: int, cypher_chunk: bytes)-> bytes:
        iv= self.derive_iv(session_id, seq_num)
        meta_data= struct.pack(">II", session_id, seq_num)
        return self.aesgcm.decrypt(iv, cypher_chunk, meta_data)
