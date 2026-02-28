# Architecture

## Vue d'ensemble
Archipel est un réseau P2P local sans serveur central. Chaque nœud est à la fois client et serveur.

## Modules
- `crypto`: génération de clés, signatures, HMAC, chiffrement des payloads
- `network`: découverte UDP multicast, base du transport
- `protocol`: format binaire des paquets
- `peer`: modèles et gestion des pairs
- `storage`: stockage local (prévu)

## Flux (Sprint 0)
1. Le nœud démarre et génère une identité.
2. Il annonce sa présence sur le multicast UDP.
3. Il écoute et découvre d'autres pairs.
