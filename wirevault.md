# WireVault — méthode employée

- **Auteur :** lyons
- **Challenge :** WireVault
- **Catégorie :** web
- **Statut :** résolu
- **Flag :** `CTF{REDACTED}`

## Déroulé de l'attaque

Un indice de cache fuyait depuis `/api/admin/status`. En anonyme, l'endpoint répondait dans un premier temps `401` accompagné de `X-Cache: MISS`. En l'interrogeant à intervalles réguliers, une fenêtre `200` arborant `X-Cache: HIT` donnait accès, le temps de sa validité, au code de règlement généré pour ops.

L'opération de transfert contrôlait puis décrémentait la consommation du code à travers deux étapes qui n'avaient rien d'atomique. Un compte banal pouvait donc soumettre ce même code sur plusieurs connexions parfaitement synchronisées. Des variantes du chemin ne différant que par la casse échappaient à la clé du limiteur OpenResty, tandis qu'Express dirigeait tout cela vers un handler unique.

Le PoC local se trouve dans [wirevault_exploit.py](../wirevault_exploit.py). Le script ouvre un compte, patiente jusqu'au cache-hit, garde le cookie de session, relâche le dernier octet au travers de 60 requêtes lancées en même temps, contrôle le solde puis achète `platinum_pass`.

## Résultats constatés

- Cache-hit remporté sur l'endpoint admin.
- La course aboutit : 39 règlements concurrents.
- Solde constaté : 195000 cents.
- `platinum_pass` acheté avec succès, le champ `flag` est renvoyé.

