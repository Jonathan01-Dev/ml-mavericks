#!/bin/bash
# Initialisation du Plan B - À exécuter une seule fois

set -e

echo "🚀 Initialisation Plan B pour Archipel"
echo "======================================"

# Création des dossiers
mkdir -p .runtime .planb logs

# Génération de la clé API si elle n'existe pas
if [ ! -f .runtime/api_key.txt ]; then
    echo "📝 Génération d'une nouvelle clé API..."
    openssl rand -hex 32 > .runtime/api_key.txt
    echo "✅ Clé générée: $(cat .runtime/api_key.txt | cut -c1-8)..."
else
    echo "✅ Clé API existante: $(cat .runtime/api_key.txt | cut -c1-8)..."
fi

# Vérification .gitignore
if ! grep -q "\.runtime/" .gitignore; then
    echo "⚠️  Ajout de .runtime/ au .gitignore"
    echo -e "\n# Plan B runtime\n.runtime/\n.planb/" >> .gitignore
fi

# Test du client
echo ""
echo "🧪 Test du client Plan B..."
python3 -c "
import sys
sys.path.insert(0, '.')
from archipel.plan_b.client import PlanBClient
client = PlanBClient()
print(f'  Status: {client.status()}')
print(f'  Health: {client.healthcheck()}')
"

echo ""
echo "✅ Plan B initialisé avec succès"
