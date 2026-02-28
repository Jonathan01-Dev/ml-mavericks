"""Tests unitaires"""

import unittest
import os
import sys

# Permet d'importer le package depuis src/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from archipel.protocol.packet import ArchipelPacket
from archipel.protocol.constants import PacketType
from archipel.crypto.manager import CryptoManager

class TestPacketProtocol(unittest.TestCase):
    
    def setUp(self):
        self.crypto = CryptoManager()
    
    def test_serialization(self):
        payload = b"test payload"
        hmac_data = os.urandom(32)
        packet = ArchipelPacket(
            PacketType.HELLO,
            self.crypto.node_id,
            payload,
            hmac_data
        )
        serialized = packet.serialize()
        deserialized = ArchipelPacket.deserialize(serialized)
        self.assertEqual(deserialized.packet_type, PacketType.HELLO)
        self.assertEqual(deserialized.node_id, self.crypto.node_id)
        self.assertEqual(deserialized.payload, payload)
    
    def test_invalid_magic(self):
        payload = b"test"
        hmac_data = os.urandom(32)
        packet = ArchipelPacket(
            PacketType.HELLO,
            self.crypto.node_id,
            payload,
            hmac_data
        )
        serialized = packet.serialize()
        # On corrompt le MAGIC (les 4 premiers octets)
        corrupted = b'BAD!' + serialized[4:]
        with self.assertRaises(ValueError):
            ArchipelPacket.deserialize(corrupted)

if __name__ == '__main__':
    unittest.main()
