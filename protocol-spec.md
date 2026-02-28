# Spécification du protocole (v1)

## En-tête
- MAGIC: 4 bytes
- TYPE: 1 byte
- NODE_ID: 32 bytes
- PAYLOAD_LEN: 4 bytes (uint32 big-endian)

## Payload
- Chiffré (E2E)
- Longueur variable

## HMAC
- SHA-256, 32 bytes

## Types de paquets
- 0x01 HELLO
- 0x02 PEER_LIST
- 0x03 MSG
- 0x04 CHUNK_REQ
- 0x05 CHUNK_DATA
- 0x06 MANIFEST
- 0x07 ACK
