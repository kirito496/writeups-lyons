# Know Your Enemy — OSINT sur l'empreinte publique laissée par BUG|PWN

- **Catégorie :** out context (OSINT)
- **Flag :** `CTF{REDACTED}` (format `CTF{surname}`)
- **Fichiers fournis :** aucun

## Énoncé

> *Before you attack a target, you study it. BUG|PWN has a public footprint
> like any other security team. There's a website, a GitHub organization,
> and a handful of social accounts. Everything you need for this challenge
> is already public. Nothing here needs to be brute forced, guessed, or bought.*
>
> *Someone who has contributed to BUG|PWN's work left their real name
> somewhere in this footprint, even though they go by a handle everywhere
> else. Find their surname.*
>
> Flag format: `CTF{surname}`

## Démarche

1. **Recensement de l'empreinte publique** : site web de BUG|PWN, organisation GitHub,
   comptes sociaux (Twitter/X, LinkedIn, etc.).
2. **Exploration de GitHub** : fouiller les dépôts de l'organisation, les commits, les
   fichiers `AUTHORS`, `CONTRIBUTORS`, les profils des contributeurs. Tout commit Git
   embarque un champ `Author:` avec un nom et un email — quiconque a commité sous son vrai
   nom plutôt que sous son handle finit ainsi dans l'historique.
3. **Recoupement** : repérer le contributeur qui arbore un pseudonyme partout, sauf à un
   endroit précis où affleure son vrai nom (nom de famille).
4. Le flag consiste en le nom de famille mis au jour, au format `CTF{surname}`.

## Enseignements

- Les commits Git regorgent d'OSINT : le champ `Author:` ne recèle pas toujours un pseudo,
  et l'historique d'un dépôt conserve les anciennes valeurs même une fois le profil
  retouché.
- `git log --format='%an <%ae>'` lancé sur un clone dresse la liste de tous les auteurs
  distincts.
- Les métadonnées (PDF, images, documents) publiées sur un site peuvent également receler
  des noms réels.

## Flag obtenu

```
CTF{REDACTED}
```

---

*Rédaction : **lyons** — BUG|PWN CTF · Know Your Enemy.*
