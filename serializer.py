"""Sérialisation des payloads"""

import struct
from typing import List, Tuple
from .constants import NODE_ID_LENGTH

class PacketSerializer:
    
    @staticmethod
    def serialize_hello(public_key: bytes, signature: bytes) -> bytes:
        if len(public_key) != 32:
            raise ValueError("Public key must be 32 bytes")
        if len(signature) != 64:
            raise ValueError("Signature must be 64 bytes")
        return public_key + signature
    
    @staticmethod
    def deserialize_hello(data: bytes) -> Tuple[bytes, bytes]:
        if len(data) != 96:
            raise ValueError("Invalid HELLO packet length")
        return data[:32], data[32:96]
    
    @staticmethod
    def serialize_peer_list(peers: List[Tuple[bytes, str, int]]) -> bytes:
        result = bytearray()
        result.extend(struct.pack('!H', len(peers)))
        for node_id, addr, port in peers:
            if len(node_id) != NODE_ID_LENGTH:
                raise ValueError("Invalid node ID length")
            result.extend(node_id)
            addr_bytes = addr.encode('ascii')
            if len(addr_bytes) > 255:
                raise ValueError("Address too long")
            result.extend(struct.pack('!B', len(addr_bytes)))
            result.extend(addr_bytes)
            result.extend(struct.pack('!H', port))
        return bytes(result)
    
    @staticmethod
    def deserialize_peer_list(data: bytes) -> List[Tuple[bytes, str, int]]:
        if len(data) < 2:
            raise ValueError("Peer list too short")
        
        offset = 0
        count = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        
        peers = []
        for _ in range(count):
            if offset + NODE_ID_LENGTH > len(data):
                raise ValueError("Truncated peer list")
            node_id = data[offset:offset+NODE_ID_LENGTH]
            offset += NODE_ID_LENGTH
            
            if offset >= len(data):
                raise ValueError("Truncated peer list")
            addr_len = data[offset]
            offset += 1
            
            if offset + addr_len + 2 > len(data):
                raise ValueError("Truncated peer list")
            addr = data[offset:offset+addr_len].decode('ascii')
            offset += addr_len
            
            port = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            
            peers.append((node_id, addr, port))
        
        return peers
