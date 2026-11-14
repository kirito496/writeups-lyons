# PWN#007 — Kernel Vault

**Auteur :** lyons

**Catégorie** : Pwn côté kernel  
**Points** : 148  
**Niveau** : Hard  
**Flag** : `FLAG{REDACTED}`

## Présentation

Un driver kernel maison `/dev/vault` s'exécute dans une VM QEMU (Linux 6.1.176). La mission : décrocher root puis parcourir `/root/flag.txt`. Le handout livre `vmlinux` (avec symboles), `bzImage`, `initramfs.cpio.gz` et `run.sh`.

## Cadre d'exécution

- QEMU x86_64, 256M de RAM
- CPU flags : **SMEP actif**, **SMAP inactif**
- BusyBox en statique, compte non-root `user`
- Driver vault incorporé au kernel (aucun module externe)

## Examen du driver

### Symboles repérés

```
vault_open       — retourne 0
vault_release    — retourne 0
vault_ioctl      — toute la logique
vault_default_notify — callback par défaut (juste ret)
```

### Opérations ioctl

| Commande | Code | Taille arg | Description |
|----------|------|-----------|-------------|
| CREATE   | 0x40085601 | 8 | Ouvre un slot (id + taille) |
| DELETE   | 0x40045602 | 4 | Détruit un slot |
| READ     | 0x40105603 | 16 | Relit les données d'un slot |
| WRITE    | 0x40105604 | 16 | Remplit un slot avec des données |
| NOTIFY   | 0x40045605 | 4 | Déclenche le callback du slot |
| LEAK     | 0x80085606 | 8 | Recopie l'adresse de vault_ioctl côté userspace |

### Organisation interne

Une table globale de 16 slots (pointeurs). Tout slot s'appuie sur un header de 32 octets (kmalloc-32) :

```
offset 0x00 : callback obfusqué (XOR avec 0x6f6f56e06f2d7f60)
offset 0x08 : argument du callback
offset 0x10 : taille du buffer de données
offset 0x18 : pointeur vers le buffer de données
```

Le buffer de données est réservé à part au moyen de `__kmalloc(size)`.

## Défaut exploité : Use-After-Free

**DELETE omet de repasser `slots[id]` à NULL après les kfree.**

Ce que fait DELETE :
1. Récupère `slots[id]` dans un registre
2. Passe par `kfree(header->data)`
3. Libère ensuite via `kfree(header)`
4. Renvoie 0

Or `slots[id]` garde la référence au header désormais libre. Les commandes READ, WRITE et NOTIFY continuent de s'appuyer dessus.

## Mise à l'exploit

### Étape 1 : Éteindre KASLR

LEAK recopie l'adresse de `vault_ioctl` en userspace. Le slide KASLR s'en déduit :

```
slide = leaked_addr - 0xffffffff8156efa0
commit_creds = 0xffffffff810a13b0 + slide
init_cred    = 0xffffffff82851000 + slide
```

### Étape 2 : UAF → mainmise sur le callback

1. **CREATE slot 0** (size=32) → header_0 tombe dans kmalloc-32, data_0 de même dans kmalloc-32
2. **DELETE slot 0** → kfree(data_0), kfree(header_0), toutefois `slots[0]` référence toujours header_0
3. **CREATE slot 1** (size=32) → kmalloc reprend la zone libérée
   - `data_1` hérite de l'emplacement de header_0
   - `slots[0]` désigne désormais `data_1`

### Étape 3 : Déposer le callback hostile

**WRITE slot 1** remplit `data_1` (soit l'ancien header_0), réécrivant au passage les champs lus comme le header du slot 0 :

```
payload[0:8]  = XOR_KEY ^ commit_creds   (callback obfusqué)
payload[8:16] = &init_cred               (argument)
```

### Étape 4 : Amorcer l'escalade

**NOTIFY slot 0** parcourt le header (devenu notre payload) :
- Décodage : `callback = XOR_KEY ^ payload[0:8] = commit_creds`
- Invocation : `commit_creds(&init_cred)`
- Le processus en cours passe root

### Étape 5 : Récupérer le flag

```sh
cat /root/flag.txt
```

## Exploit (assembleur x86_64, ~8.5 KB en statique)

L'exploit a été rédigé en assembleur brut (NASM) afin d'en réduire la taille et de permettre un upload rapide via base64+gzip dans la VM. Seuls les syscalls `open`, `ioctl`, `getuid`, `write` et `execve` entrent en jeu.

Le binaire pèse 8576 octets ; une fois passé en gzip+base64, il tient en 744 caractères et s'expédie en une unique commande shell.

## Notions techniques

- **SMAP inactif** : le kernel lit la mémoire userspace sans détour (le contournement SMEP ne s'impose que pour le code, pas pour les données)
- **SMEP actif** : impossible de rebondir directement sur du code userspace, mais l'approche `commit_creds(&init_cred)` s'en passe
- **Obfuscation XOR** : le callback est masqué par un XOR à clé fixe, que l'on déjoue aisément une fois la base connue
- La réservation en kmalloc-32 pour data ET header (dès que size ≤ 32) rend la réutilisation prévisible
