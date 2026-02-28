# Lancer le script de démo automatisé
bash demo/demo.sh

# Ou étape par étape:
# 1. Générer 3 identités
for i in 1 2 3; do python -m archipel.main keygen --node node-$i; done

# 2. Démarrer 3 nœuds (3 terminaux)
python -m archipel.main start --port 3883$i --discover

# 3. Partager un fichier
python -m archipel.main serve ./demo/test_50mb.bin --port 38834

# 4. Télécharger depuis un autre nœud
python -m archipel.main download <FILE_ID> --peers 127.0.0.1:38834
