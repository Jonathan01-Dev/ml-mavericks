"""Plan B local API (Flask)."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict

from flask import Flask, jsonify, request

from archipel.crypto.manager import CryptoManager
from archipel.protocol.packet import ArchipelPacket
from archipel.protocol.constants import PacketType

from . import config, security, crypto_box, tcp_server


ROLE_VALUES = {"server", "client"}


def _load_role(base_dir: Path) -> str:
    path = config.role_path(base_dir)
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value in ROLE_VALUES:
            return value
    return "client"


def _save_role(base_dir: Path, value: str) -> None:
    path = config.role_path(base_dir)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")


def create_app(base_dir: Path) -> Flask:
    app = Flask(__name__)

    api_key = security.load_or_create_api_key(base_dir)
    enc_key = security.load_or_create_enc_key(base_dir)
    role = _load_role(base_dir)

    crypto_mgr = CryptoManager()
    tcp_mgr = tcp_server.TCPManager()

    def _auth_failed():
        return jsonify({"error": "unauthorized"}), 401

    def _require_auth() -> bool:
        supplied = request.headers.get("X-API-Key", "")
        return security.constant_time_compare(supplied, api_key)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/status")
    def status():
        if not _require_auth():
            return _auth_failed()
        return jsonify({
            "role": role,
            "node_id": crypto_mgr.node_id.hex(),
        })

    @app.get("/role")
    def get_role():
        if not _require_auth():
            return _auth_failed()
        return jsonify({"role": role})

    @app.post("/role")
    def set_role():
        nonlocal role
        if not _require_auth():
            return _auth_failed()
        data = request.get_json(silent=True) or {}
        value = str(data.get("role", "")).lower()
        if value not in ROLE_VALUES:
            return jsonify({"error": "invalid_role"}), 400
        role = value
        _save_role(base_dir, role)
        return jsonify({"role": role})

    @app.post("/token/rotate")
    def rotate_token():
        nonlocal api_key
        if not _require_auth():
            return _auth_failed()
        api_key = security.rotate_api_key(base_dir)
        return jsonify({"api_key": api_key})

    @app.post("/crypto/encrypt")
    def encrypt_payload():
        if not _require_auth():
            return _auth_failed()
        data = request.get_json(silent=True) or {}
        plaintext_b64 = data.get("plaintext_b64", "")
        aad_b64 = data.get("aad_b64", "")
        try:
            plaintext = crypto_box.b64decode(plaintext_b64)
            aad = crypto_box.b64decode(aad_b64) if aad_b64 else b""
            encrypted = crypto_box.encrypt(enc_key, plaintext, aad)
            return jsonify({"ciphertext_b64": crypto_box.b64encode(encrypted)})
        except Exception as exc:
            return jsonify({"error": "encrypt_failed", "detail": str(exc)}), 400

    @app.post("/crypto/decrypt")
    def decrypt_payload():
        if not _require_auth():
            return _auth_failed()
        data = request.get_json(silent=True) or {}
        ciphertext_b64 = data.get("ciphertext_b64", "")
        aad_b64 = data.get("aad_b64", "")
        try:
            ciphertext = crypto_box.b64decode(ciphertext_b64)
            aad = crypto_box.b64decode(aad_b64) if aad_b64 else b""
            plaintext = crypto_box.decrypt(enc_key, ciphertext, aad)
            return jsonify({"plaintext_b64": crypto_box.b64encode(plaintext)})
        except Exception as exc:
            return jsonify({"error": "decrypt_failed", "detail": str(exc)}), 400

    @app.post("/packet/serialize")
    def packet_serialize():
        if not _require_auth():
            return _auth_failed()
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        try:
            packet_type = int(data.get("packet_type"))
            payload = crypto_box.b64decode(data.get("payload_b64", ""))
            hmac_data = crypto_box.b64decode(data.get("hmac_b64", ""))
            node_id_hex = data.get("node_id_hex")
            node_id = bytes.fromhex(node_id_hex) if node_id_hex else crypto_mgr.node_id
            packet = ArchipelPacket(packet_type, node_id, payload, hmac_data)
            serialized = packet.serialize()
            return jsonify({"data_b64": crypto_box.b64encode(serialized)})
        except Exception as exc:
            return jsonify({"error": "serialize_failed", "detail": str(exc)}), 400

    @app.post("/packet/deserialize")
    def packet_deserialize():
        if not _require_auth():
            return _auth_failed()
        data = request.get_json(silent=True) or {}
        try:
            raw = crypto_box.b64decode(data.get("data_b64", ""))
            packet = ArchipelPacket.deserialize(raw)
            return jsonify({
                "packet_type": packet.packet_type,
                "node_id_hex": packet.node_id.hex(),
                "payload_b64": crypto_box.b64encode(packet.payload),
                "hmac_b64": crypto_box.b64encode(packet.hmac),
            })
        except Exception as exc:
            return jsonify({"error": "deserialize_failed", "detail": str(exc)}), 400

    @app.get("/packet/types")
    def packet_types():
        if not _require_auth():
            return _auth_failed()
        return jsonify({
            "HELLO": PacketType.HELLO,
            "PEER_LIST": PacketType.PEER_LIST,
            "MSG": PacketType.MSG,
            "CHUNK_REQ": PacketType.CHUNK_REQ,
            "CHUNK_DATA": PacketType.CHUNK_DATA,
            "MANIFEST": PacketType.MANIFEST,
            "ACK": PacketType.ACK,
        })

    @app.get("/tcp/status")
    def tcp_status():
        if not _require_auth():
            return _auth_failed()
        return jsonify(tcp_mgr.status())

    @app.post("/tcp/start")
    def tcp_start():
        if not _require_auth():
            return _auth_failed()
        data = request.get_json(silent=True) or {}
        host = data.get("host", "127.0.0.1")
        port = int(data.get("port", 0))
        host, port = tcp_mgr.start(host, port)
        return jsonify({"running": True, "host": host, "port": port})

    @app.post("/tcp/stop")
    def tcp_stop():
        if not _require_auth():
            return _auth_failed()
        tcp_mgr.stop()
        return jsonify({"running": False})

    @app.post("/tcp/send")
    def tcp_send():
        if not _require_auth():
            return _auth_failed()
        data = request.get_json(silent=True) or {}
        host = data.get("host")
        port = int(data.get("port", 0))
        payload_b64 = data.get("payload_b64", "")
        if not host or port <= 0:
            return jsonify({"error": "invalid_target"}), 400
        try:
            payload = tcp_server.b64decode(payload_b64)
            response = tcp_mgr.send(host, port, payload)
            return jsonify({"response_b64": tcp_server.b64encode(response)})
        except Exception as exc:
            return jsonify({"error": "tcp_send_failed", "detail": str(exc)}), 400

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Archipel Plan B API")
    parser.add_argument("--host", default=config.DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    parser.add_argument("--base-dir", default=str(Path.cwd()))
    args = parser.parse_args()

    base_dir = Path(args.base_dir).resolve()
    app = create_app(base_dir)
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
