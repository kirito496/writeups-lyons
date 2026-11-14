# PWN#Delta — Vault Terminal PowerPC (fuite de canari + gadgets PPC)

- **Auteur :** lyons
- **Cible :** `<HOST>:<PORT>` (Vault Terminal, plateforme PowerPC 32-bit)
- **Catégorie :** pwn
- **Flag :** `CTF{REDACTED}` (cf. règle de non-conservation des flags)
- **Fichiers fournis :** binaire ELF PowerPC 32-bit

## Cadre

Déclinaison PowerPC du Vault Terminal : même boucle de menu que PWN#001 et PWN#002 (nom puis message). On a affaire à un ELF 32-bit big-endian, relié statiquement et non strippé (1949 symboles lisibles). Canary, NX et Partial RELRO sont en place ; PIE est absent, d'où des adresses figées pour tout le binaire.

## Inventaire

### Mécanismes de défense

| Protection   | État                |
|---|---|
| Canary       | Activé              |
| NX           | Activé              |
| RELRO        | Partiel             |
| PIE          | Désactivé           |
| Liaison      | Statique            |

Le binaire statique embarque `system()` et la chaîne `"/bin/sh"` à des adresses fixes ; aucune fuite libc ne s'impose.

### Agencement de la pile

- Tampon du nom : 64 octets.
- Saisie du nom : 65 octets (`read(0, buf, 0x41)`) pour un tampon de 64, soit un débordement d'un seul octet (off-by-one) qui écrase le LSB du canari.
- Saisie du message : 108 octets dans le même tampon de 64, débordement maîtrisé franchissant le canari et l'adresse de retour.

### Adresses essentielles (statiques, sans ASLR)

| Élément           | Adresse       |
|---|---|
| `gadget_load_r9`  | `0x100007cc`  |
| `gadget_vec_r3`   | `0x10000834`  |
| `system()`        | `0x100020d0`  |
| `"/bin/sh"`       | `0x10074850`  |

## Faille

### Fuite du canari

Le nom est saisi sur 65 octets dans un tampon de 64. Le soixante-cinquième octet vient écraser le NUL de poids faible du canari. Puisque ce nom est ensuite recopié par `printf("Hello, %s\n", buf)` sans qu'aucune terminaison NUL ne soit ajoutée, les 7 octets restants du canari s'échappent dans la réponse. On reconstitue le canari complet : `b"\x00" + leak[64:71]`.

Ce procédé est le même que pour les variantes x86 (PWN#001, PWN#002, PWN#Epsilon).

### Débordement par le message

Les 108 octets du message excèdent le tampon de 64 et permettent d'écrire au-delà du canari, du frame pointer sauvegardé et de l'adresse de retour.

## Passage à l'attaque

### Spécificité PPC : le back-chain pointer

Sur PowerPC, le prologue `stwu r1, -0x30(r1)` dépose l'ancien `r1` (le back-chain pointer) précisément dans le slot de pile que `gadget_load_r9` consulte pour remplir `r9`. Plutôt que de lutter contre cette contrainte architecturale, l'exploit en tire parti : la valeur de `r9` se déduit implicitement du back-chain, ce qui allège la chaîne.

### Enchaînement de l'exploit

1. **Fuite du canari** : transmettre 65 octets en guise de nom, puis recueillir les 7 octets du canari dans la réponse `Hello, ...`.

2. **Assemblage du payload message** :
   - Octets `[0..63]` : bourrage du tampon.
   - Octets `[64..71]` : canari reconstitué.
   - Octet 84 : chaîne littérale `"sh\0\0"` — voilà la commande que `system()` lira depuis son propre cadre d'appel.
   - Adresse de retour : désigne `gadget_load_r9` (`0x100007cc`), qui remplit `r9` depuis la pile (par le back-chain pointer), puis file vers `gadget_vec_r3` (`0x10000834`), qui charge `r3` (premier argument PPC) avant de sauter vers `system()` (`0x100020d0`).

3. **Invocation de `system()`** : `system()` reçoit la chaîne `"sh"` comme argument par `r3`, lequel vise le slot du tampon à l'offset 84. Le binaire étant statique et non-PIE, chaque adresse est figée et aucune fuite additionnelle n'est requise.

### Pourquoi aucune fuite libc

Le binaire est relié statiquement : `system()` et `"/bin/sh"` sont embarqués dans le binaire lui-même. Les adresses ne bougent pas (PIE absent). L'ASLR est neutralisé par construction.

## Issue

Le shell distant est tombé. Le flag a été récupéré puis validé.

```
$ id
uid=65534(nobody) gid=65534(nogroup)
$ cat /flag/flag.txt
CTF{REDACTED}
```

## Écueils traversés

- **Back-chain PPC** : le prologue `stwu` réécrit un slot de pile dont le gadget dépend. Chercher à le déjouer est contre-productif ; l'intégrer à la chaîne reste la bonne option.
- **Big-endian** : l'ordre des octets des adresses dans le payload est inversé vis-à-vis des variantes x86. Passer par `p32()` de pwntools en réglant `context.endian = 'big'`.
- **Argument de `system()`** : sous PPC, le premier argument voyage via `r3`, non via la pile. La chaîne `"sh\0\0"` déposée dans le tampon est désignée par `r3` grâce au gadget `gadget_vec_r3`.
- **Taille du payload** : le message est plafonné à 108 octets, ce qui laisse une marge étroite pour les gadgets. La chaîne minimale (deux gadgets + `system()`) loge dans ce gabarit.

## Enseignements

1. **Architectures exotiques** : les conventions PPC (back-chain, registre d'argument, big-endian) divergent de x86, mais les principes de base (fuite du canari, ROP) demeurent identiques.
2. **Binaire statique = pas de libc externe** : dès que le binaire embarque `system()` et `"/bin/sh"`, toute fuite libc devient superflue. L'exploitation est ASLR-proof d'office.
3. **Composer avec l'architecture plutôt que la combattre** : tirer parti du back-chain pointer au lieu de l'affronter allège la chaîne et ramène la taille du payload.
4. **Gadgets plantés** : `gadget_load_r9` et `gadget_vec_r3` ont été semés exprès par l'auteur du challenge. Les repérer dans les symboles (binaire non strippé) fait toute la clé de la résolution.
