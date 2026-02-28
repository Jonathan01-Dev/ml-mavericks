#!/bin/bash
# ===================================================
# ARCHIPEL - GÉNÉRATEUR SPRINT 0 - VERSION CORRIGÉE
# Copiez CE SCRIPT EN ENTIER et exécutez-le
# ===================================================

set -e

echo "=================================="
echo "ARCHIPEL - GÉNÉRATION SPRINT 0"
echo "=================================="

# Création du dossier de travail
mkdir -p archipel
cd archipel

# Création structure de dossiers
echo "📁 Création structure..."
mkdir -p network protocol crypto peer storage tests
touch __init__.py
touch network/__init__.py protocol/__init__.py crypto/__init__.py peer/__init__.py storage/__init__.py tests/__init__.py

# FICHIER 1: protocol/constants.py
cat > protocol/constants.py << 'PYEOF'
"""ARCHIPEL Protocol Constants - V1 - FIGÉ"""

MAGIC = b'\x41\x52\x43\x48'

class PacketType:
    HELLO = 0x01
    PEER_LIST = 0x02
    MSG = 0x03
    CHUNK_REQ = 0x04
    CHUNK_DATA = 0x05
    MANIFEST = 0x06
    ACK = 0x07

NODE_ID_LENGTH = 32
HMAC_LENGTH = 32
MAX_PACKET_SIZE = 65536
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - (4 + 1 + NODE_ID_LENGTH + 4 + HMAC_LENGTH)

UDP_DISCOVERY_PORT = 38833
TCP_BASE_PORT = 38834
DISCOVERY_INTERVAL = 30
PEER_TIMEOUT = 120
TCP_TIMEOUT = 10
MAX_CONCURRENT_CONNECTIONS = 50

CHUNK_SIZE = 32768
PYEOF

# FICHIER 2: protocol/packet.py
cat > protocol/packet.py << 'PYEOF'
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
PYEOF

# FICHIER 3: crypto/manager.py
cat > crypto/manager.py << 'PYEOF'
"""Gestionnaire cryptographique"""

import os
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..protocol.constants import NODE_ID_LENGTH

class CryptoManager:

    def __init__(self):
        self._private_key = ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self.node_id = hashlib.sha256(
            self._public_key.public_bytes_raw()
        ).digest()[:NODE_ID_LENGTH]
        self._symmetric_key = None

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes_raw()

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def verify(self, signature: bytes, data: bytes, public_key: bytes) -> bool:
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            pub_key.verify(signature, data)
            return True
        except Exception:
            return False

    def compute_hmac(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def verify_hmac(self, key: bytes, data: bytes, received_hmac: bytes) -> bool:
        computed = self.compute_hmac(key, data)
        return hmac.compare_digest(computed, received_hmac)

    def encrypt_payload(self, plaintext: bytes, aad: bytes = b'') -> bytes:
        if self._symmetric_key is None:
            raise RuntimeError("Symmetric key not established")
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(self._symmetric_key)
        ciphertext = cipher.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    def decrypt_payload(self, encrypted_data: bytes, aad: bytes = b'') -> bytes:
        if self._symmetric_key is None:
            raise RuntimeError("Symmetric key not established")
        if len(encrypted_data) < 12:
            raise ValueError("Encrypted data too short")
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        cipher = ChaCha20Poly1305(self._symmetric_key)
        return cipher.decrypt(nonce, ciphertext, aad)

    def establish_symmetric_key(self, peer_public_key: bytes) -> bytes:
        peer_key = ed25519.Ed25519PublicKey.from_public_bytes(peer_public_key)
        shared_secret = self._private_key.exchange(peer_key)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ARCHIPEL-SESSION-KEY',
        )
        self._symmetric_key = hkdf.derive(shared_secret)
        return self._symmetric_key
PYEOF

# FICHIER 4: peer/models.py
cat > peer/models.py << 'PYEOF'
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
PYEOF

# FICHIER 5: network/udp_discovery.py
cat > network/udp_discovery.py << 'PYEOF'
"""Découverte UDP"""

import socket
import struct
import threading
import time
from typing import Optional, Callable, Set
from ..protocol.constants import UDP_DISCOVERY_PORT, DISCOVERY_INTERVAL

class UDPDiscoveryService:

    MULTICAST_GROUP = '224.0.0.251'

    def __init__(self, node_id: bytes, port: int, callback: Optional[Callable] = None):
        self.node_id = node_id
        self.tcp_port = port
        self.callback = callback
        self.running = False
        self.socket = None
        self.thread = None
        self._lock = threading.Lock()
        self.discovered_peers: Set[bytes] = set()

    def start(self):
        if self.running:
            return

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('', UDP_DISCOVERY_PORT))

            mreq = struct.pack("4sl", socket.inet_aton(self.MULTICAST_GROUP), socket.INADDR_ANY)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.socket.settimeout(1.0)

            self.running = True
            self.thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.thread.start()

        except Exception as e:
            self._cleanup()
            raise RuntimeError(f"Failed to start UDP discovery: {e}")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)
        self._cleanup()

    def _cleanup(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None

    def _listen_loop(self):
        while self.running:
            try:
                data, addr = self.socket.recvfrom(1024)
                if len(data) == 34:
                    node_id = data[:32]
                    port = struct.unpack('!H', data[32:34])[0]

                    with self._lock:
                        if node_id not in self.discovered_peers:
                            self.discovered_peers.add(node_id)
                            if self.callback:
                                self.callback(node_id, addr[0], port)
            except socket.timeout:
                continue
            except Exception:
                continue

    def announce(self):
        if not self.socket:
            return
        packet = self.node_id + struct.pack('!H', self.tcp_port)
        try:
            self.socket.sendto(packet, (self.MULTICAST_GROUP, UDP_DISCOVERY_PORT))
        except Exception:
            pass

    def start_announce_loop(self):
        def _loop():
            while self.running:
                self.announce()
                time.sleep(DISCOVERY_INTERVAL)
        thread = threading.Thread(target=_loop, daemon=True)
        thread.start()
PYEOF

# FICHIER 6: protocol/serializer.py
cat > protocol/serializer.py << 'PYEOF'
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
PYEOF

# FICHIER 7: tests/test_packet.py
cat > tests/test_packet.py << 'PYEOF'
"""Tests unitaires"""

import unittest
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from protocol.packet import ArchipelPacket
from protocol.constants import PacketType
from crypto.manager import CryptoManager

class TestPacketProtocol(unittest.TestCase):

    def setUp(self):
        self.crypto = CryptoManager()

    def test_serialization(self):
        payload = b"test payload"
        hmac = os.urandom(32)
        packet = ArchipelPacket(
            PacketType.HELLO,
            self.crypto.node_id,
            payload,
            hmac
        )
        serialized = packet.serialize()
        deserialized = ArchipelPacket.deserialize(serialized)
        self.assertEqual(deserialized.packet_type, PacketType.HELLO)
        self.assertEqual(deserialized.node_id, self.crypto.node_id)
        self.assertEqual(deserialized.payload, payload)

    def test_invalid_magic(self):
        payload = b"test"
        hmac = os.urandom(32)
        packet = ArchipelPacket(
            PacketType.HELLO,
            self.crypto.node_id,
            payload,
            hmac
        )
        serialized = packet.serialize()
        corrupted = b'TEST' + serialized[4:]
        with self.assertRaises(ValueError):
            ArchipelPacket.deserialize(corrupted)

if __name__ == '__main__':
    unittest.main()
PYEOF

# FICHIER 8: main.py
cat > main.py << 'PYEOF'
"""Point d'entrée ARCHIPEL"""

import argparse
import time
from crypto.manager import CryptoManager
from network.udp_discovery import UDPDiscoveryService

def main():
    parser = argparse.ArgumentParser(description='ARCHIPEL Node')
    parser.add_argument('--port', type=int, default=38834, help='TCP port')
    parser.add_argument('--discover', action='store_true', help='Enable discovery')
    args = parser.parse_args()

    print("🚀 ARCHIPEL Node Starting...")
    crypto = CryptoManager()
    print(f"📋 Node ID: {crypto.node_id.hex()[:16]}...")

    if args.discover:
        discovery = UDPDiscoveryService(crypto.node_id, args.port)
        discovery.start()
        discovery.start_announce_loop()
        print(f"📡 Discovery enabled on port {args.port}")

    print("✅ Node ready")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
        if args.discover:
            discovery.stop()

if __name__ == "__main__":
    main()
PYEOF

# FICHIER 9: requirements.txt
cat > requirements.txt << 'PYEOF'
cryptography==41.0.7
PYEOF

# FICHIER 10: README.md
cat > README.md << 'PYEOF'
# ARCHIPEL - Sprint 0

## Installation
```bash
pip install -r requirements.txt
```
PYEOF
