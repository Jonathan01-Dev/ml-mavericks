"""ARCHIPEL Packet Structure"""

import struct
from .constants import *

class ArchipelPacket:
    __slots__ = ['packet_type', 'node_id', 'payload', 'hmac']
    
    def __init__(self, packet_type: int, node_id: bytes, payload: bytes, hmac: bytes):
        if not isinstance(packet_type, int) or packet_type < 0x01 or packet_type > 0x07:
            raise ValueError(f"Invalid packet type: {packet_type}")
        if not isinstance(node_id, bytes) or len(node_id) != NODE_ID_LENGTH:
            raise ValueError(f"Node ID must be {NODE_ID_LENGTH} bytes")
        if not isinstance(payload, bytes):
            raise ValueError("Payload must be bytes")
        if len(payload) > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {len(payload)} > {MAX_PAYLOAD_SIZE}")
        if not isinstance(hmac, bytes) or len(hmac) != HMAC_LENGTH:
            raise ValueError(f"HMAC must be {HMAC_LENGTH} bytes")
        
        self.packet_type = packet_type
        self.node_id = node_id
        self.payload = payload
        self.hmac = hmac
    
    def serialize(self) -> bytes:
        payload_len = len(self.payload)
        fmt = f'!4s B {NODE_ID_LENGTH}s I {payload_len}s {HMAC_LENGTH}s'
        return struct.pack(
            fmt,
            MAGIC,
            self.packet_type,
            self.node_id,
            payload_len,
            self.payload,
            self.hmac
        )
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'ArchipelPacket':
        if len(data) < 4 + 1 + NODE_ID_LENGTH + 4 + HMAC_LENGTH:
            raise ValueError("Packet too short")
        
        offset = 0
        if data[offset:offset+4] != MAGIC:
            raise ValueError("Invalid MAGIC")
        offset += 4
        
        packet_type = data[offset]
        offset += 1
        
        node_id = data[offset:offset+NODE_ID_LENGTH]
        offset += NODE_ID_LENGTH
        
        payload_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        
        if payload_len > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload length exceeds maximum: {payload_len}")
        if len(data) < offset + payload_len + HMAC_LENGTH:
            raise ValueError("Packet truncated")
        
        payload = data[offset:offset+payload_len]
        offset += payload_len
        
        hmac_received = data[offset:offset+HMAC_LENGTH]
        
        return cls(packet_type, node_id, payload, hmac_received)
