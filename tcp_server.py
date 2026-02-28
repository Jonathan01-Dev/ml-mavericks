"""Simple TCP server/client helpers for Plan B."""

from __future__ import annotations

import base64
import socket
import socketserver
import threading
from dataclasses import dataclass
from typing import Optional, Tuple


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(1024 * 1024)
        if not data:
            return
        # Echo back payload
        self.request.sendall(data)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


@dataclass
class TCPServerState:
    host: str
    port: int
    thread: threading.Thread
    server: ThreadedTCPServer


class TCPManager:
    def __init__(self) -> None:
        self._state: Optional[TCPServerState] = None

    def start(self, host: str, port: int) -> Tuple[str, int]:
        if self._state is not None:
            return self._state.host, self._state.port
        server = ThreadedTCPServer((host, port), _TCPHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._state = TCPServerState(host=host, port=server.server_address[1], thread=thread, server=server)
        return self._state.host, self._state.port

    def stop(self) -> None:
        if self._state is None:
            return
        self._state.server.shutdown()
        self._state.server.server_close()
        self._state = None

    def status(self) -> dict:
        if self._state is None:
            return {"running": False}
        return {"running": True, "host": self._state.host, "port": self._state.port}

    def send(self, host: str, port: int, payload: bytes, timeout: float = 5.0) -> bytes:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(payload)
            return sock.recv(1024 * 1024)


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))

