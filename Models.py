"""Modèles de données pairs"""

import time
from dataclasses import dataclass
from ..protocol.constants import NODE_ID_LENGTH

@dataclass(frozen=True)
class Peer:
    node_id: bytes
    public_key: bytes
    address: str
    port: int
    
    def __post_init__(self):
        if len(self.node_id) != NODE_ID_LENGTH:
            raise ValueError(f"Node ID must be {NODE_ID_LENGTH} bytes")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("Public key must be 32 bytes")
    
    def key(self) -> bytes:
        return self.node_id

@dataclass
class PeerState:
    peer: Peer
    last_seen: float
    is_active: bool = True
    connection_attempts: int = 0
    
    def update_seen(self):
        self.last_seen = time.time()
        self.connection_attempts = 0
    
    def is_expired(self, timeout: float) -> bool:
        return (time.time() - self.last_seen) > timeout
