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
                        if node_id == self.node_id:
                            continue
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
