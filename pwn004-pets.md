# PWN#004 — Pets Shelter (FSOP House of Apple 2 + empoisonnement de freelist)

- **Auteur :** lyons
- **Cible :** `<HOST>:<PORT>` (Pets Shelter, ELF x86-64 C++ strippé)
- **Catégorie :** pwn
- **Flag :** `CTF{REDACTED}` (voir la règle de non-persistance des flags)
- **Fichiers fournis :** binaire ELF x86-64 C++ strippé, 18568 octets

## Mise en contexte

Un refuge pour animaux de compagnie, implémenté en C++. L'exécutable est un ELF x86-64 strippé (plus aucun symbole). La libc n'est pas livrée ; le serveur distant fait tourner la **glibc 2.43-5**, reconnue par empreinte (fingerprinting des offsets GOT).

On retrouve l'allocateur de pool de PWN#003, à ceci près que la rotation de l'encodage `mangle` passe de 13 à 7 :

```
mangle(ptr, node) = ptr XOR rol(node, 7)
```

## Phase de reconnaissance

### Mécanismes de défense

| Protection   | État     |
|---|---|
| Canary       | Activé   |
| NX           | Activé   |
| RELRO        | Full     |
| PIE          | Activé   |
| Symboles     | Strippés |

### Le piège du point d'entrée

Dans l'en-tête ELF, le champ `e_entry` désigne `0x269e`, une adresse qui déclenche un **SIGSEGV** avant même `main` — manœuvre délibérée. Le véritable `_start` siège à `0x1130`. Lors de l'analyse statique, il faut corriger ou contourner `e_entry`.

### L'allocateur de pool

L'ossature de PWN#003 revient :
- pool dont la freelist est encodée par `mangle` avec `rol 7` ;
- allocations de classe 2 (taille `0x80`) ;
- 16 indices de notes au total, chaque écriture en consommant 2 (single-use).

### L'opération "poke pet"

L'opération `poke` enchaîne `read` + `memcpy` à l'intérieur d'un objet pourtant libéré : c'est le primitif d'écriture après libération (write-after-free). De là découle l'empoisonnement de la freelist, comme au PWN#003.

## La faille

### Write-after-free par le poke

L'opération `poke pet` inscrit ses données dans un objet déjà relâché. Le contenu efface le pointeur de freelist encodé du chunk libéré, ce qui autorise l'aiguillage de la prochaine allocation vers une adresse arbitraire.

### Un budget serré

16 indices de notes, 2 engloutis par écriture : le plafond s'établit à 8 opérations d'écriture. Toute la chaîne d'exploitation doit être pensée au cordeau pour tenir dans ce cadre.

## Exploitation

### Stratégie : FSOP House of Apple 2

Les contraintes du terrain — `execve` hors de portée directe, aucun gadget ROP évident dans ce binaire C++ strippé — aiguillent vers la FSOP (File Stream Oriented Programming) et la technique "House of Apple 2" :

1. Réorienter le pointeur `_IO_list_all` de la libc vers une structure `FILE` contrefaite.
2. Provoquer le nettoyage des flux au moyen de `exit(0)`, qui déroule `_IO_list_all` et sollicite les vtables de chaque flux.
3. La vtable truquée dévie alors l'exécution vers `system("/bin/sh")`.

### Étape 1 — Fuite libc

On empoisonne la freelist (même logique qu'au PWN#003, `rol 7` remplaçant `rol 13`) pour détourner une allocation vers les métadonnées d'un objet, puis on y substitue au callback un `puts@PLT` braqué sur `puts@GOT`.

```
libc_base = puts_leak - puts_offset_glibc_2.43
```

### Étape 2 — Assemblage de la structure FILE contrefaite

La structure `FILE` truquée et ses données wide annexées se décomposent ainsi :
- **Fake FILE** : `0xe0` octets (soit 224).
- **Wide-data** : `0xe8` octets (soit 232).

Leur écriture s'étale sur **quatre allocations de classe 2** (taille `0x80` chacune), financées par les indices restants.

### Piège décisif : " /bin/sh" précédé d'un espace

La chaîne `"/bin/sh"` se termine sur un octet de poids faible `0x2f`, dont le bit 3 vaut 1. Or ce bit, dans la structure `FILE`, fait précisément office de drapeau `_IO_NO_WRITES`. Dès que ce drapeau se lève, la vtable de sortie n'est plus invoquée et tout le montage s'effondre.

**Remède** : adopter `" /bin/sh"` (espace en tête), dont l'octet de poids faible tombe à `0x20` (bit 3 à 0). L'appel `system(" /bin/sh")` demeure opérant, le shell brûlant les espaces initiaux.

### Étape 3 — Empoisonner `_IO_list_all`

Le même empoisonnement de freelist sert à inscrire dans `_IO_list_all` l'adresse de la structure FILE contrefaite.

### Étape 4 — Mise à feu via exit(0)

Il reste à faire partir `exit(0)` (soit par la sortie normale du programme, soit par ROP). Le nettoyage des flux balaie `_IO_list_all`, tombe sur la structure contrefaite et déclenche `system(" /bin/sh")` par la vtable détournée.

## Résultat

La FSOP a livré son shell. Le flag est ressorti aussi bien de la variable d'environnement `FLAG=` que de `/flag/flag.txt`.

```
CTF{REDACTED}
```

## Obstacles rencontrés

- **`e_entry` piégé** : le point d'entrée ELF (`0x269e`) fait crasher d'un SIGSEGV. Le `_start` authentique attend à `0x1130`. Passé inaperçu, ce piège bloque toute l'analyse statique.
- **Rotation `rol 7`** : ici `mangle` tourne sur `rol 7`, et non sur le `rol 13` de PWN#003. Recycler l'exploit du PWN#003 sans corriger la rotation conduit à un échec muet.
- **Budget de 16 indices** : deux indices par écriture, huit opérations au maximum. La fake FILE réclame 4 allocations, auxquelles s'ajoutent 2 pour la fuite libc et 2 pour l'empoisonnement final. Zéro marge de manœuvre.
- **`"/bin/sh"` contre `" /bin/sh"`** : l'octet de poids faible de `"/bin/sh"` (`0x2f`) dresse `_IO_NO_WRITES` et empêche la vtable de partir. Un espace liminaire (`" /bin/sh"`, octet `0x20`) neutralise l'obstacle.
- **glibc 2.43-5** : la libc du serveur diffère de celle des PWN#001/002/003 (2.42-13). Offsets de `system`, de `puts`, de `_IO_list_all` et structures internes : tout est à recalculer. L'empreinte de symboles fait l'identification.
- **Fake FILE éclatée sur plusieurs allocations** : entre la structure `FILE` (0xe0) et la wide-data (0xe8), rien ne tient dans une allocation unique de 0x80 ; le tout se répartit sur quatre allocations contiguës.

## Enseignements

1. **House of Apple 2** : lorsque ROP classique ou `execve` sont barrés, la FSOP par `_IO_list_all` offre une issue redoutable — à condition de connaître la structure `FILE` de la libc visée au détail près.
2. **Se méfier des bits de drapeau** : en FSOP, le moindre octet de la structure `FILE` est signifiant. Celui de poids faible de l'argument de commande peut croiser les drapeaux internes du flux. Testez plusieurs variantes de la chaîne.
3. **Budget d'allocation** : un quota d'indices impose de dessiner toute la chaîne avant d'écrire le premier octet. Aucune place pour l'expérimentation itérative.
4. **Pièges anti-analyse** : falsifier `e_entry` relève de l'arsenal anti-reversement classique. Contrôlez toujours la validité du point d'entrée avant de lancer l'analyse.
5. **Fingerprinting de libc** : en l'absence de libc livrée, l'empreinte des offsets GOT désigne la version exacte. Des outils comme `libc-database` ou `patchelf` automatisent cette étape.
