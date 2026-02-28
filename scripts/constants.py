"""ARCHIPEL Protocol Constants - V1 - FIGÉ"""

# Packet Magic (ARCH en ASCII)
MAGIC = b'\x41\x52\x43\x48'  # "ARCH"

# Packet Types (1 byte)
class PacketType:
    HELLO = 0x01      # Initial handshake
    PEER_LIST = 0x02  # Peer exchange
    MSG = 0x03        # Text message
    CHUNK_REQ = 0x04  # Request chunk
    CHUNK_DATA = 0x05 # Chunk data transfer
    MANIFEST = 0x06   # File manifest
    ACK = 0x07        # Acknowledgment

# Protocol Constants
NODE_ID_LENGTH = 32      # bytes
HMAC_LENGTH = 32         # bytes
MAX_PACKET_SIZE = 65536  # 64KB
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - (4 + 1 + NODE_ID_LENGTH + 4 + HMAC_LENGTH)  # ~65500 bytes

# Network Constants
UDP_DISCOVERY_PORT = 38833
TCP_BASE_PORT = 38834
DISCOVERY_INTERVAL = 30  # seconds
PEER_TIMEOUT = 120       # seconds
TCP_TIMEOUT = 10         # seconds
MAX_CONCURRENT_CONNECTIONS = 50

# Fragmentation
CHUNK_SIZE = 32768  # 32KB chunks for file transfer
