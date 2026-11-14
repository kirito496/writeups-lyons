# PWN#002 — Deep Vault Terminal (PIE + ROP pext + open/read/write)

- **Auteur :** lyons
- **Cible :** `<HOST>:<PORT>` (Deep Vault Terminal, ELF x86-64 PIE strippé)
- **Catégorie :** pwn
- **Flag :** `CTF{REDACTED}` (voir la règle de non-persistance des flags)
- **Fichiers fournis :** binaire ELF x86-64 PIE (strippé)

## Mise en contexte

Deuxième volet de la série Vault Terminal. L'exécutable est un ELF x86-64 soumis à PIE et débarrassé de ses symboles. La libc demeure celle de PWN#001 (Debian GLIBC 2.42-13). Le filtrage seccomp gagne en finesse cette fois : un BPF brut n'interdit que `execve` (59) et `openat` (257), tout en **laissant passer `open` (2)**.

## Phase de reconnaissance

### Mécanismes de défense

| Protection   | État                              |
|---|---|
| Canary       | Activé                            |
| NX           | Activé                            |
| RELRO        | Full                              |
| PIE          | Activé (adresses aléatoires)      |
| seccomp BPF  | Bloque `execve`(59), `openat`(257)|
| Symboles     | Strippés                          |

### Une fuite de la base PIE via le banner

Dès le démarrage, le service publie un banner où figure un sceau :

```
Vault seal: %016lx
```

La valeur imprimée vaut `base + 0x13a6` ; la base PIE s'en déduit par `seal_value - 0x13a6`.

### Fuite du canary

Le mécanisme de PWN#001 se rejoue à l'identique : 73 octets lus pour un tampon de 72, le soixante-treizième efface le LSB nul du canary, et `printf("%s")` laisse échapper les 7 octets de poids fort.

### Examen minutieux du BPF seccomp

Le BPF brut frappe d'interdiction :
- `execve` (syscall 59) : shell impossible.
- `openat` (syscall 257) : l'ouverture de fichiers par `openat` est prohibée.

Mais `open` (syscall 2) **échappe au filtrage**. Toute la clé est là : `open()` ouvre le fichier, `read()` en tire le contenu, `write()` le recrache sur stdout.

### Le chemin du flag entreposé en .bss

Au lancement, le binaire décode la chaîne `"/flag/flag.txt"` dans une zone `.bss` inscriptible posée à `PIE + 0x4070`. La base PIE connue, ce chemin devient joignable à une adresse calculable.

### Gadgets : le `pop rdi` classique manque à l'appel

Aucun gadget `pop rdi; ret` conventionnel ne figure dans le binaire. L'auteur y a semé un trio de gadgets mobilisant l'instruction BMI2 `pext` :

```
pext rdi, rax, rcx
```

Ce trio garnit `rdi` à partir de `rax` et `rcx`, deux registres pilotés via d'autres gadgets de pile. Repérer ces gadgets dans un binaire strippé réclame un balayage exhaustif des opcodes.

## La faille

- **Fuite PIE** : le banner `Vault seal: %016lx` met la base PIE à nu.
- **Fuite canary** : même off-by-one qu'au PWN#001.
- **Débordement de pile** : le message déborde du tampon et livre le contrôle de l'adresse de retour.
- **seccomp incomplet** : `open(2)` reste permis malgré le verrou posé sur `openat(257)`.

## Exploitation

### Étape 1 — Fuite libc

Une chaîne ROP s'appuie sur les gadgets `pext` pour garnir `rdi` avec l'adresse de `puts@GOT` (déduite de la base PIE), puis appeler `puts@PLT` :

```
padding[72] + canary[8] + rbp[8] + ROP_chain
```

La chaîne procède ainsi :
1. Charge `rdi = puts@GOT` au moyen du trio `pext`.
2. Invoque `puts@PLT`, qui imprime l'adresse résolue de `puts`.
3. Rebascule vers la machine d'état à l'offset `PIE + 0x1676` pour relancer la boucle.

On obtient : `libc_base = puts_leak - puts_offset_glibc_2.42`.

### Étape 2 — open + read + write

Les deux bases (libc et PIE) étant acquises :

1. **`open(PIE + 0x4070, O_RDONLY)`** : ouvre `"/flag/flag.txt"` (la chaîne dort déjà décodée en `.bss`). Le syscall `open` (2) franchit le filtre seccomp sans encombre.
2. **`read(fd, buf, n)`** : transfère le contenu du fichier dans un tampon sous contrôle.
3. **`write(1, buf, n)`** : recopie ce contenu sur stdout (fd 1).

Pour ce second temps, on mobilise les gadgets libc classiques (`pop rdi`, `pop rsi`, `pop rdx`, `syscall`), dont les adresses se calculent depuis la base libc.

### Rebond sur la machine d'état

L'offset `0x1676` du binaire marque l'entrée de la machine d'état (state machine) qui orchestre la boucle nom/message. Y replonger après l'étape 1 relance l'exploitation en vue de l'étape 2 sans nouvelle connexion — le canary ne bouge pas au sein d'une même session.

## Résultat

Le contenu de `/flag/flag.txt` est ressorti par l'enchaînement `open` + `read` + `write`, puis la soumission a abouti.

```
CTF{REDACTED}
```

## Obstacles rencontrés

- **Absence de `pop rdi`** : privé du gadget `pop rdi; ret` habituel, il faut mobiliser les gadgets `pext` BMI2 semés par l'auteur. Sans balayage complet des opcodes, ils demeurent introuvables.
- **`openat` contre `open`** : seccomp frappe `openat` (257) et épargne `open` (2). Seule la lecture du BPF brut révèle cette nuance, invisible dans un simple `seccomp-tools dump`.
- **Binaire strippé sous PIE** : sans symboles, cerner gadgets et fonctions PLT/GOT impose une analyse manuelle, ou un outil comme ROPgadget/ropper avec le binaire rechargé à la bonne base.
- **Chemin du flag en .bss** : `"/flag/flag.txt"` est décodé dès le démarrage en `.bss`. Inutile de pousser la chaîne sur la pile ; visez directement l'adresse `.bss`.

## Enseignements

1. **Décortiquer le BPF brut** : un `seccomp-tools dump` peut laisser passer des finesses. Instruire le filtre BPF pas à pas met en lumière que `open` (2) reste permis là où `openat` (257) est frappé d'interdiction.
2. **Gadgets BMI2 (`pext`)** : rares dans les binaires ordinaires, les instructions BMI2 peuvent avoir été semées exprès par l'auteur du challenge. Dans un binaire strippé, scanner les opcodes bruts s'avère incontournable.
3. **Chaîne `open` + `read` + `write`** : dès que `execve` tombe, lire directement le fichier via `open`/`read`/`write` (ou `sendfile`) reste l'alternative éprouvée.
4. **Machine d'état réexploitable** : rebondir sur l'entrée de la boucle permet d'enchaîner plusieurs temps dans une seule connexion, à l'abri d'une re-randomisation du canary comme de l'ASLR.
