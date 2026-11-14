# OT#004 — Chemical Reactor (protocole binaire custom, style OPC-UA)

- **Auteur :** lyons

- **Cible :** `<HOST>:<PORT>` — énoncé consultable ici : https://otctf.pages.dev/ot-004-chemical-reactor/
- **Catégorie :** OT / ICS
- **Flag :** `CTF{REDACTED}`
- **Protocole :** TCP binaire maison (vendu comme « OPC-UA-style », en réalité pas de l'OPC UA binaire véritable)

## Cadre du challenge

On pilote un réacteur chimique doté d'un Safety Instrumented System (SIS) dont la mission est d'ordonner un arrêt avant que la moindre condition dangereuse ne devienne soutenue. L'address space annoncé : `Objects (ns=0, id=85)` → `Reactor Controller` (tags process) + `Safety System` (trip/protection). Zéro documentation fournie : « discover them by talking to the endpoint » — ni source, ni binaire, ni carte des nœuds.

## Enquête — cadrage du transport (confirmé)

- La connexion TCP s'ouvre, **aucune bannière** : c'est au client d'ouvrir le dialogue.
- **Rien à voir avec de l'OPC UA binaire authentique** : un HEL OPC UA (`HELF` + taille LE + corps), essayé tantôt à la main tantôt via `asyncua`, se solde par une fermeture immédiate.
- Le framing, arrêté au terme d'essais successifs : **`[uint32 big-endian longueur][payload]`**, la longueur ne couvrant que le payload (en-tête exclu) :
  - `len=8` + 3 octets → connexion toujours vivante, le serveur patiente sur les 5 octets manquants.
  - `len=4` avec l'en-tête seul → vivant : il attend 4 octets de payload.
  - `len=0` (trame vide) → vivant : simple no-op, le serveur repart sur la trame d'après.
  - 5 octets `AAAAA` → déconnexion (`len=0x41414141` ≈ 1 Go : un plafond est franchi → rejet).
  - Un HEL OPC UA coupe pour la même raison (`"HELF"` lu comme une longueur astronomique).

## Enquête — couche message (le verrou qui a tenu un moment)

Devant toute trame complète mal formée, le serveur **coupe sans un mot** et **ne rend jamais la moindre réponse** quel que soit l'envoi (ni avant ni après `shutdown(SHUT_WR)`) : le brute-force à l'aveugle du format de payload devient prohibitif (un essai = une connexion neuve, le tout sous rate-limit). Tentatives restées vaines durant cette phase — chacune aboutit à une fermeture silencieuse :

- Texte brut framé : `hello`, `HELLO`, `Read`, `Browse`, `Write`, `PING`, `BROWSE 85\n`, `WRITE 85 1\n`, etc.
- JSON framé : `{"op":"hello"}`, `{"type":"Hello"}`, `{"op":"browse","node":"ns=0;i=85"}`, etc.
- Binaire framé : opcodes `0x00`-`0x09` + `u32be(85)`, octets isolés `'H'/'B'/'R'/'W'`, en-tête OPC UA `HEL`/`HELF` + corps, NodeId OPC UA sur 2 octets.

**Chausse-trape relevé** : un timeout de lecture ne prouve rien quant à la survie de la connexion — le serveur tarde parfois à émettre le FIN. Seule l'arrivée effective d'octets vaut signal positif ; autrement, on s'imagine à tort qu'un essai « passe ».

**Rate-limit constaté** : ~20 connexions rapprochées (≈10/min) → ban (EOF instantané sur tout, y compris en passif), levé après ~8 min de silence complet. Un rythme de ~5 connexions/min (12 s entre chaque) demeure tenable sur 10+ connexions sans attirer de ban.

## Protocole véritable (dénouement)

Le format véritable n'est pas sorti d'un brute-force à l'aveugle : il a été reconstitué en recoupant plusieurs hypothèses avec les comportements constatés — **`[op:u8][len:u32 little-endian][payload]`**. Le blocage venait d'une lecture du premier octet comme une longueur big-endian : il s'agit en réalité de l'opcode, et la longueur qui le suit est en little-endian (contrairement au transport, en big-endian).

- `0x01` handshake (payload vide) → renvoie `0x81` accompagné du session id (`u32` LE).
- `0x03` read : payload `<I H I>` (`sid, ns, nid`) → en retour, corps `u32 | status:u8 | type:u8 | value`.
- `0x04` write : payload `<I H I>` (`sid, ns, nid`) + `type:u8` + `value` → le status se lit dans `body[4]`.
- Types de valeur : `1` = i32, `2` = f64, `3` = bool, `4` = string.

### Nœuds déterminants

| Namespace.ID | Rôle |
|---|---|
| `(1, 1001)` | `HeaterPower` (f64) — commande process |
| `(1, 1002)` | `Temperature` (lecture) |
| `(1, 1003)` | `Pressure` (lecture) |
| `(2, 2001)` | `TripEnable` (bool) — **SIS** |
| `(2, 2008)` | `PretripLatch` (bool) — **SIS** |
| `(2, 2003)` | `Tripped` (lecture) |
| `(2, 2004)` | `Flag` (string) — ne se peuple qu'en condition dangereuse |

## La brèche

En théorie, le SIS vit à l'écart du process controller ; en pratique, il se greffe sur la **même address space et la même session** : les opérations génériques read/write (`0x03`/`0x04`) suffisent à écrire dans ses nœuds comme dans n'importe quel tag process. Aucune séparation de privilège entre « lire/écrire une process value » et « modifier l'état d'un système de sécurité ».

## Déroulé

1. Handshake `0x01` → mettre la main sur la session id.
2. Write `TripEnable = False` sur `(2, 2001)` puis `PretripLatch = False` sur `(2, 2008)` → le SIS se retrouve dans l'incapacité d'ordonner l'arrêt.
3. Write `HeaterPower = 100.0` sur `(1, 1001)` → runaway thermique entretenu (la température grimpe sans jamais être coupée).
4. Poller `(2, 2004)` en boucle : le flag ne se remplit que tant que la condition dangereuse demeure active (`Tripped` doit rester à `0`) — lire pendant le runaway, jamais après coup.

## Script (solveur)

Le solver complet vit dans `challenges/ot-004-chemical-reactor/solve.py` : handshake, extinction des deux drapeaux du SIS, write `HeaterPower=100.0`, puis polling de `(2, 2004)` jusqu'à ce que le flag apparaisse.

## Issue

La température a grimpé entre ~540-620 °C sans que `Tripped` ne bascule une seule fois. Le flag a été extrait de `(2, 2004)` : `CTF{REDACTED}` — remis à l'utilisateur pour soumission.

## Chausse-trapes

- Transport (framing avec longueur `u32be`) et couche message (`op:u8` + longueur `u32 LE`) jouent sur **deux endianness différentes** — s'y égarer donne l'impression d'un protocole intégralement opaque, alors qu'une seule couche interne diffère.
- Quand le serveur garde un silence total devant une trame mal formée (jamais le moindre message d'erreur), le brute-force à l'aveugle rapporte peu ; recouper les indices (nom de protocole annoncé, comportements de fermeture) reste plus payant que fuzzer à vide.
- Le flag reste **subordonné à l'état dangereux en cours** : une lecture post-trip ne montre rien, la condition doit être maintenue pendant qu'on lit.

## Portée générale

Face à tout protocole exposant un SIS/safety layer, la question à se poser systématiquement : la couche sécurité partage-t-elle l'espace d'adressage et le canal d'écriture de la couche process ? Si oui, et si une même session atteint les deux, la « protection » se réduit à une convention logicielle dépourvue de toute isolation réelle.

---

*Rédaction : **lyons** — BUG|PWN CTF · OT#004 Chemical Reactor.*
