# Plan B Backend — API Locale

## Objectif
Fournir un backend local sécurisé, 100% hors-ligne, sans base de données, capable de prendre le relais si l'application principale tombe.

## Diagramme logique (ASCII)
```
+------------------------+             +----------------------+
|  App principale (GUI)  |             |  Watchdog Plan B      |
|  src/archipel/main.py  |---crash----->|  tools/plan_b_watchdog.py
+-----------+------------+             +----------+-----------+
            |                                     |
            |                                     v
            |                            +------------------+
            |                            |  API Plan B      |
            |                            |  Flask local     |
            |                            |  127.0.0.1:5055  |
            |                            +---------+--------+
            |                                      |
            v                                      v
      (normal run)                         Clients locaux (Python)
```

## Endpoints
Tous les endpoints (sauf `/health`) exigent `X-API-Key`.

- `GET /health`
  - Retourne `{"status":"ok"}`.
- `GET /status`
  - Retourne rôle + `node_id`.
- `GET /role`
  - Retourne le rôle courant.
- `POST /role`
  - Body: `{"role":"server"|"client"}`.
- `POST /token/rotate`
  - Génère une nouvelle clé API.
- `POST /crypto/encrypt`
  - Body: `{"plaintext_b64":..., "aad_b64":...}`.
- `POST /crypto/decrypt`
  - Body: `{"ciphertext_b64":..., "aad_b64":...}`.
- `POST /packet/serialize`
  - Body: `{"packet_type":1..7,"node_id_hex":...,"payload_b64":...,"hmac_b64":...}`.
- `POST /packet/deserialize`
  - Body: `{"data_b64":...}`.
- `GET /packet/types`
  - Retourne la table des types.
- `GET /tcp/status`
  - État du serveur TCP local.
- `POST /tcp/start`
  - Body: `{"host":"127.0.0.1","port":0}` (port 0 = auto).
- `POST /tcp/stop`
  - Arrête le serveur TCP local.
- `POST /tcp/send`
  - Body: `{"host":"127.0.0.1","port":5056,"payload_b64":...}`.

## Sécurisation
- Clé API 256-bit générée localement (`.runtime/api_key.txt`).
- Clé de chiffrement AES-GCM 256-bit (`.runtime/enc_key.bin`).
- Aucune connexion externe.
- Aucune base de données.
- Fichiers runtime locaux protégés (permissions 600/700).

## Exemple d'intégration Python
```python
from archipel.plan_b.client import PlanBClient

client = PlanBClient("http://127.0.0.1:5055", api_key="<API_KEY>")
print(client.status())
client.set_role("server")
```

## Installation
### Linux
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m archipel.plan_b.api --base-dir /home/jb/Bureau/24H/archipel
```

### Windows (PowerShell)
```
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
py -m archipel.plan_b.api --base-dir C:\\path\\to\\archipel
```

## Watchdog
```
python3 tools/plan_b_watchdog.py \
  --target /home/jb/Bureau/24H/archipel/src/archipel/main.py \
  --base-dir /home/jb/Bureau/24H/archipel
```
