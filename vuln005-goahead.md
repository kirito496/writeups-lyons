# VULN#005 — Acme Gateway (serveur web embarqué GoAhead)

**Auteur :** lyons

> Challenge bugpwn `<HOST>:<PORT>`, catégorie Vuln Research, 30 pts.

## GoAhead BF1 Basic-Auth Bypass (SA-2026-0001)

**Catégorie :** web
**Mots-clés :** goahead, embedthis, basic-auth, bypass, bf1, blowfish, iot, embedded
**CVE / Advisory :** GOAHEAD-SA-2026-0001 (critique)

### Contexte

Embedthis GoAhead ≤ 6.1.0 (et branches 6.0.x sans correctif). La release 6.1.1
corrige le bug, mais la chaîne de version `ME_VERSION` affichée par un binaire
n'atteste en rien la présence du patch — contrôler la source. Point de départ :
`src/auth.c`, fonction `websVerifyPasswordFromFile`.

### Indicateurs

- Serveur embarqué qui proclame (ou dissimule) `GoAhead`.
- `WWW-Authenticate: Basic realm="example.com"` (realm posé par défaut).
- `auth.txt` renfermant un utilisateur dont le hash démarre par `BF1:` (format
  Blowfish salé maison : `BF1:<rounds>:<salt>:<hash>`).

### Méthode

Sur la version vulnérable :

```c
if (sstarts(wp->user->password, "BF1:")) {
    success = websCheckPassword(wp->password, wp->user->password); // vrai check
    wfree(wp->password);
    wp->password = sclone(wp->user->password);   // password == stored hash
}
...
if (wp->digest) {
    success = pmatch(wp->password, wp->digest);
} else {
    success = pmatch(wp->password, wp->user->password); // compare la chaîne à elle-même
}
return success;
```

Le verdict du véritable contrôle se fait écraser par un `pmatch(x, x)` qui renvoie
invariablement vrai. Pour tout utilisateur stocké en `BF1:`, le Basic auth accepte
n'importe quel mot de passe. Seule exigence : connaître le **nom** d'un user
`BF1:` porteur du rôle exigé par la route (`manage` pour `/admin/`).

### Commandes génériques

```bash
# 1) Repérer la cible et l'auth demandée
curl -I http://<HOST>:<PORT>/<ADMIN_PATH>

# 2) Trouver le nom d'un user BF1 (voir fiche config leak ci-dessous ou wordlist)
curl -s http://<HOST>:<PORT>/config/auth.txt | grep '^user'

# 3) Login avec n'importe quel mot de passe
curl -i -u "<BF1_USER>:anything" http://<HOST>:<PORT>/<ADMIN_PATH>
# → 302 + Set-Cookie: -goahead-session-=::webs.session::...
```

### Pièges

- Devant un reverse-proxy (nginx `limit_req`), les tentatives se heurtent au
  rate-limit (429). Espacer chaque essai de 15–20 s, sans bruteforce massif.
- Le bypass ne fonctionne QUE sur les users `BF1:`. Les users MD5 restent à l'abri.
- La route visée doit correspondre aux `abilities` de l'utilisateur contourné.
- Le `realm="example.com"` traduit le défaut `ME_GOAHEAD_REALM` : ne surtout pas
  y voir un vrai domaine.

### Validation

- Réponse `302` vers la page d'après-login + cookie `-goahead-session-=...`.
- Les requêtes suivantes munies de ce cookie atteignent le contenu protégé sans
  transmettre l'en-tête `Authorization`.

### Références

- GoAhead 6.1.1 release notes (11 advisories SA-2026-0001..0011).
- Source consultable : `src/auth.c:598-625`.

---

## Fichiers de config GoAhead exposés sous `/config/`

**Catégorie :** web
**Mots-clés :** goahead, config leak, auth.txt, route.txt, information disclosure

### Contexte

Le `fileHandler` de GoAhead délivre tel quel tout fichier posé sous le
`documents root`. Quand un intégrateur range `auth.txt` et `route.txt` dans un
sous-dossier `web/config/` (commodité de packaging oblige), ces fichiers se
retrouvent accessibles sans auth tant qu'aucune route ne les couvre.

### Indicateurs

- Une requête sur `/config/` renvoie `302` vers `/config/index.html` (signe que
  `web/config/` existe) tandis que `/config/index.html` répond 404.
- Aucune route restrictive déclarée dans la portion visible du `route.txt`
  (du moins lorsqu'on parvient à le lire).

### Méthode

Énumérer les noms plausibles. Fichiers de configuration GoAhead par défaut :
`auth.txt`, `route.txt`. Logs/backups habituels : `users.txt`, `users.json`,
`config.ini`, `config.conf`, `goahead.conf`, `.htaccess`, `README`.

```bash
for f in auth.txt route.txt users.txt users.json config.ini goahead.conf; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<HOST>:<PORT>/config/$f")
  echo "$code $f"
done
```

### Pièges

- Le path traversal classique (`/../auth.txt`) est neutralisé par
  `websNormalizeUriPath` + `websValidUriChars`. Il faut impérativement que le
  fichier réside dans le `documents root`.
- Les routes `route uri=/...` se matchent par préfixe : une route catch-all
  `uri=/` dépourvue d'`auth=` laisse filer tout ce qui n'a pas déjà été capté.

### Validation

- Le `auth.txt` récupéré contient des lignes `user name=<X> password=<HASH>
  roles=<R>`. Les hash `BF1:...` deviennent exploitables d'emblée via
  [GoAhead BF1 Basic-Auth Bypass](#goahead-bf1-basic-auth-bypass-sa-2026-0001).

---

## Reconnaissance de GoAhead derrière nginx (en-tête Server usurpé)

**Catégorie :** web
**Mots-clés :** fingerprint, goahead, nginx, reverse proxy, header spoof

### Contexte

Certains déploiements embarqués interposent nginx devant GoAhead et imposent
`Server: nginx` dans la réponse. L'empreinte GoAhead demeure toutefois traçable
par d'autres signaux.

### Indicateurs

- Corps d'erreur façon GoAhead :
  `<html><head><title>Document Error: Not Found</title></head><body><h2>Access Error: Not Found</h2></body></html>`
  (face à nginx qui affiche `<center><h1>...</h1></center><hr><center>nginx</center>`).
- Redirection `302` d'un répertoire vers `/.../index.html` avec un body qui
  divulgue une adresse interne : `This document has moved to a new <a
  href="http://<INTERNAL_IP>:<PORT>/...">location</a>.` → fuite de l'IP/port
  du backend.
- `WWW-Authenticate: Basic realm="example.com"` sur toute route protégée.
- `Last-Modified` au format non standard : `Thu Oct 15 21:44:55 2026`
  (format `ctime`, et non RFC 7231).
- Cookie de session baptisé `-goahead-session-` dont la valeur démarre par
  `::webs.session::`.

### Méthode

1. Distinguer le 404 nginx renvoyé pour une méthode interdite (`TRACE`) de celui
   d'une URL inconnue (`/foo`) : le premier traverse nginx seul, le second est
   délivré par GoAhead → styles divergents.
2. Interroger `/` : si GoAhead bascule vers `/index.html` avec le body
   "This document has moved…", l'empreinte est authentifiée.

### Pièges

- La valeur `Server:` ne saurait jamais être prise pour une autorité.
- En présence de plusieurs backends (upstream pool), l'IP divulguée peut changer.

---
