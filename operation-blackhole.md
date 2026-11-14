# Operation BLACKHOLE 1→8 — Analyse pcap d'une attaque DDoS

- **Auteur :** lyons

- **Catégorie :** out context (forensics réseau)
- **Flag :** réponse attendue à chaque question (pas de format `CTF{...}` standard)
- **Fichier fourni :** `CTF1.pcapng` (capture réseau d'un incident DDoS visant Acme Corp)

## Énoncé

> *Our subsidiary, Acme Corp, was hit by a DDoS attack last night.
> The SOC team captured the network traffic during the incident.
> Objective: Analyze CTF1.pcapng and answer the 8 questions.*

Les 8 challenges reposent sur le **même fichier pcap** et posent chacun une question
d'analyse forensique réseau. L'outil roi est **Wireshark** (ou `tshark` en ligne de
commande).

## Questions et façon de les traiter

### BLACKHOLE 1 (5 pts) — « What is the IP address of the attacking machine? »

Repérer l'IP source à l'origine du plus gros volume de trafic (flood). Sous Wireshark :
`Statistics → Endpoints → IPv4`, avec un tri par paquets ou octets.

Flag : `CTF{REDACTED}`

### BLACKHOLE 2 (5 pts) — « What is the target's IP address? »

L'IP de destination dominante du flood. Même logique : `Statistics → Conversations → IPv4`,
la paire la plus fournie en paquets livre d'un coup la source (Q1) et la cible (Q2).

Flag : `CTF{REDACTED}`

### BLACKHOLE 3 (10 pts) — « Which TCP port is targeted by the HTTP attack? »

Filtrer sur l'IP source repérée en Q1 : `ip.src == <attacker>`. Regarder le port TCP de
destination (`tcp.dstport`). Un flood HTTP vise typiquement 80 ou 8080.

Flag : `CTF{REDACTED}`

### BLACKHOLE 4 (10 pts) — « Which HTTP method is used for flooding? »

Filtre Wireshark : `http.request && ip.src == <attacker>`. Contrôler le champ
`http.request.method`. Un DDoS HTTP des plus ordinaires : `GET` ou `POST`.

Flag : `CTF{REDACTED}`

### BLACKHOLE 5 (10 pts) — « Which User-Agent is associated with the malicious requests? »

Filtre : `http.request && ip.src == <attacker>`. Ajouter la colonne `http.user_agent` ou
lire les headers d'une requête. Le User-Agent du bot se distingue souvent (outil de
stress-test, chaîne générique ou fantaisiste).

Flag : `CTF{REDACTED}`

### BLACKHOLE 6 (15 pts) — « What is the duration of the attack, in seconds? »

Filtrer sur les requêtes de l'attaquant : `ip.src == <attacker>`. Noter le timestamp du
premier paquet puis du dernier. Avec tshark :

```bash
tshark -r CTF1.pcapng -Y "ip.src == <attacker>" -T fields -e frame.time_epoch | \
  awk 'NR==1{first=$1} END{printf "%.0f\n", $1-first}'
```

Flag : `CTF{REDACTED}`

### BLACKHOLE 7 (15 pts) — « How many HTTP requests does the capture contain? »

```bash
tshark -r CTF1.pcapng -Y "http.request" | wc -l
```

Vigilance : dénombrer **toutes** les requêtes HTTP du pcap (et non uniquement celles de
l'attaquant), sauf mention explicite « malicious requests » dans la question.

Flag : `CTF{REDACTED}`

### BLACKHOLE 8 (30 pts) — « What is the flag hidden in an HTTP header? »

Passer en revue les headers HTTP atypiques. Traquer un header custom embarquant `CTF{` ou
`battleCTF{` :

```bash
tshark -r CTF1.pcapng -Y "http" -T fields -e http.request.full_uri -e http.response.code \
  -e http.file_data -e http.request.line | grep -iE 'ctf\{|flag'
```

Ou bien sous Wireshark : `Edit → Find Packet → String → "CTF{"` appliqué aux bytes du
paquet.

Flag : `CTF{REDACTED}`

## Enseignements

- `Statistics → Conversations` sous Wireshark révèle d'emblée la paire attaquant/cible.
- `tshark -T fields -e <champ>` autorise l'extraction de n'importe quelle valeur à grande
  échelle.
- Les headers HTTP custom constituent un lieu de dissimulation classique pour les flags dans
  les pcap.
- Contrôler systématiquement si la question vise *tout* le trafic ou uniquement celui de
  l'attaquant.

---

*Rédaction : **lyons** — BUG|PWN CTF · Operation BLACKHOLE 1→8.*
