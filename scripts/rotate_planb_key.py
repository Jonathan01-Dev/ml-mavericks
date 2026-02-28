#!/usr/bin/env python3
"""
Rotation des clés API Plan B
Usage: python rotate_planb_key.py [--backup]
"""

import os
import sys
import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime
from getpass import getpass
import secrets

def generate_api_key() -> str:
    """Génère une clé API sécurisée (32 bytes hex)"""
    return secrets.token_hex(32)

def backup_current_key(key_path: Path):
    """Sauvegarde l'ancienne clé"""
    if key_path.exists():
        backup_dir = Path(".runtime/backups")
        backup_dir.mkdir(exist_ok=True)
        
        old_key = key_path.read_text().strip()
        backup_file = backup_dir / f"api_key_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        backup_file.write_text(old_key)
        
        print(f"✅ Ancienne clé sauvegardée: {backup_file}")
        return True
    return False

def update_env_file(new_key: str):
    """Met à jour le fichier .env avec la nouvelle clé"""
    env_path = Path(".env")
    content = []
    
    if env_path.exists():
        content = env_path.read_text().splitlines()
    
    # Chercher et remplacer la ligne ARCHIPEL_PLANB_KEY
    key_line = f"ARCHIPEL_PLANB_KEY={new_key}"
    found = False
    
    for i, line in enumerate(content):
        if line.startswith("ARCHIPEL_PLANB_KEY="):
            content[i] = key_line
            found = True
            break
    
    if not found:
        content.append(key_line)
    
    env_path.write_text("\n".join(content) + "\n")
    print("✅ Fichier .env mis à jour")

def main():
    parser = argparse.ArgumentParser(description="Rotation des clés API Plan B")
    parser.add_argument("--backup", action="store_true", help="Sauvegarder l'ancienne clé")
    parser.add_argument("--force", action="store_true", help="Forcer sans confirmation")
    args = parser.parse_args()
    
    key_path = Path(".runtime/api_key.txt")
    
    # Backup si demandé
    if args.backup and key_path.exists():
        backup_current_key(key_path)
    
    # Génération nouvelle clé
    new_key = generate_api_key()
    
    # Afficher un aperçu
    print(f"\n🔑 Nouvelle clé générée: {new_key[:8]}...{new_key[-8:]}")
    
    if not args.force:
        confirm = input("Confirmer le remplacement? (oui/non): ")
        if confirm.lower() not in ['oui', 'o', 'yes', 'y']:
            print("❌ Opération annulée")
            return
    
    # Sauvegarde dans le fichier
    key_path.parent.mkdir(exist_ok=True)
    key_path.write_text(new_key + "\n")
    print(f"✅ Clé sauvegardée: {key_path}")
    
    # Mise à jour .env
    update_env_file(new_key)
    
    # Afficher le hash de vérification
    key_hash = hashlib.sha256(new_key.encode()).hexdigest()
    print(f"🔐 SHA256: {key_hash[:16]}...")
    
    print("\n📋 Instructions:")
    print("  1. Redémarre l'API Plan B")
    print("  2. Teste avec: python -c 'from archipel.plan_b.client import PlanBClient; print(PlanBClient().ping())'")

if __name__ == "__main__":
    main()
