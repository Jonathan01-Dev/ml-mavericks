# Analyse du script Bash (générateur Sprint 0)

## Rôle
Le script Bash `tools/generatorBash.sh` est un générateur de projet. Il ne lance pas de réseau ni de logique P2P en production ; il crée l'arborescence et les fichiers initiaux pour le Sprint 0.

## Ce qu'il fait
- Crée un dossier `archipel/` et la structure `network/`, `protocol/`, `crypto/`, `peer/`, `storage/`, `tests/`.
- Génère les modules Python de base :
  - `protocol/constants.py` : constantes réseau et format de paquet.
  - `protocol/packet.py` : sérialisation/désérialisation des paquets.
  - `crypto/manager.py` : primitives crypto et helpers HMAC/chiffrement.
  - `peer/models.py` : modèles pour pairs.
  - `network/udp_discovery.py` : découverte UDP multicast.
  - `protocol/serializer.py` : sérialisation d'objets simples.
  - `tests/test_packet.py` : tests unitaires.
  - `main.py` : point d'entrée minimal.
  - `requirements.txt`, `README.md`.

## Observations
- Le script sert à **standardiser** un dépôt Sprint 0.
- Il ne contient pas de logique de bascule serveur/client ni d'auth complète.
- Pour un “Plan B” backend, il faut **encapsuler** les primitives existantes dans une API locale.

## Décision d'architecture
Le Plan B est implémenté comme un module Python autonome (`src/archipel/plan_b`) avec une API Flask locale et un watchdog. Cela permet de réutiliser les modules générés par le script Bash sans modifier leur logique interne.
