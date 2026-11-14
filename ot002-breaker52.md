# OT#002 — Breaker 52 (protocole binaire custom, attaque Aurora)

- **Auteur :** lyons

- **Cible :** `<HOST>:<PORT>` (pilotage du disjoncteur d'un générateur, raccordement à une sous-station d'interconnexion)
- **Catégorie :** OT / ICS
- **Flag :** `CTF{REDACTED}` (cf. la règle de non-persistance des flags)
- **Protocole :** TCP propriétaire, trames de requête figées à 5 octets

## Mise en contexte

Il s'agit du contrôleur du disjoncteur de couplage (tie-breaker) reliant un générateur à une sous-station d'interconnexion. Objectif : « Détruire physiquement le générateur, puis récupérer le flag qui enregistre l'incident. » D'entrée de jeu, le briefing précise que le **relais de vérification de synchronisme (dispositif ANSI 25) n'est PAS PRÉSENT** — l'indice entier tient en une ligne.

## Caractérisation du protocole

- **TCP binaire propriétaire** : chaque requête occupe exactement **5 octets**, agencés `[opcode][arg0][arg1][arg2][arg3]`.
- Aucune bannière à l'ouverture ; le serveur attend une entrée. La connexion est **persistante** (une session enchaîne plusieurs commandes).
- **Chaque opcode impose un cadrage de réponse fixe**, à respecter au quart de tour : sinon le flux d'octets se désaligne et toutes les lectures suivantes partent en dérive :
  - `0x01` → **11 octets** de télémétrie : `[status=00][float32 LE angle_réseau][float32 LE angle_générateur][disjoncteur_fermé][00]`
  - `0x02..0x05` → **1 octet**
  - tout autre opcode → **1 octet** `0xff`
- Les opcodes valides se limitent à `0x01..0x05`.

## Table des opcodes

| opcode | signification |
|--------|---------------|
| `0x01` | télémétrie (deux angles de phase, bit du disjoncteur) |
| `0x02` | lecture de l'état du disjoncteur (0 = ouvert) |
| `0x03` | **état du générateur** : `01` en ligne · `00` hors ligne · **`02` = DÉTRUIT** |
| `0x04` | ouverture du disjoncteur |
| `0x05` arg=1 | **fermeture du disjoncteur** |

## Physique du simulateur

- `angle_réseau` et `angle_générateur` parcourent 0 à 360°. Le générateur tourne à une fréquence légèrement différente, donc l'**angle de glissement Δ = (réseau − générateur) mod 360** s'accumule à ~5°/s.
- Une connexion toute neuve démarre **synchronisée** (Δ≈0). Refermer le disjoncteur dans cette fenêtre Δ≈0 vaut *synchronisation sûre* → aucun effet.
- Faute de **vérification de synchronisme**, la fermeture aboutit quel que soit **Δ**. Déclencher proche de **Δ ≈ 180°** (phases en opposition) produit le transitoire de couple destructeur = **Aurora**.

## Déroulé de l'attaque

1. Établir la connexion, solliciter `0x01`, puis déduire `Δ = (réseau − générateur) mod 360`.
2. Laisser filer le temps jusqu'à `|Δ − 180| ≤ ~6°`.
3. À cet instant précis, émettre `0x05 01 00 00 00` (fermer).
4. Quelques cycles durant, `0x03` répond `02` (générateur détruit) et le **flag transite dans les réponses** : parcourir tous les octets à la recherche de `CTF{`.

## Épure de l'exploit

```python
# socket persistant, cadrage exact (11 octets si opcode==0x01, sinon 1)
# boucle: lire 0x01 -> d=(réseau-générateur)%360
#   si abs(d-180)<=6: envoyer b'\x05\x01\x00\x00\x00'
# puis lire télémétrie/0x03 et regex le flux pour CTF{...}
```

## Issue

Flag en poche après avoir refermé le disjoncteur en opposition de phase (Δ ≈ 180°).

```
CTF{REDACTED}
```

## Chausse-trapes

- **Dérive du flux** : préférer un timeout-and-drain aux longueurs exactes fait varier `0x03` « aléatoirement » entre 00/01/02 et brûle des heures. Le cadrage précis par opcode constitue la trouvaille attendue.
- **Boutisme des floats** : les deux angles sont en **little-endian** — éprouver les deux boutismes sans tarder.
- **Fermeture déclenchée au hasard** (Δ encore faible en début de connexion) → « rien ne se passe », et l'on en déduit à tort que la commande close est fautive.

## Racine historique

Le scénario rejoue l'**INL Aurora Generator Test de 2007** : un générateur diesel physiquement détruit en refermant hors synchronisme le disjoncteur de couplage. La vulnérabilité tient à l'absence d'interlock de sécurité sur le fil, en rien à un bug mémoire.

---

*Rédaction : **lyons** — BUG|PWN CTF · OT#002 Breaker 52.*
