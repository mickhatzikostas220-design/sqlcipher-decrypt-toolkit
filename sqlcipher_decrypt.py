#!/usr/bin/env python3
"""
sqlcipher_decrypt.py
Toolkit for Bosch / automotive SQLCipher-encrypted SQLite files
(phonebook.db, call logs, messages, etc.) from head units such as the
one in a 2025 Nissan Rogue.

The database body is strong AES encryption (SQLCipher). You cannot
recover contents without the key. This tool does four jobs:

  fingerprint  Confirm a file uses the same SQLCipher-style encryption.
  try          Test a list of weak/default passphrases (fast, usually fails).
  decrypt      Decrypt ONE file with a key you supply, auto-detecting the
               SQLCipher parameter profile. Writes a plain .sqlite you can
               open in any SQLite tool.
  batch        Decrypt every matching file in a folder with one key.
  huntkey      Search a firmware dump / binary for candidate keys and test
               each against the database automatically.

Key forms:
  passphrase   plain text, e.g.  mysecret
  raw key      64 hex chars with --raw, e.g. --raw 00112233...ff  (32 bytes)

Examples:
  python3 sqlcipher_decrypt.py fingerprint phonebook.db
  python3 sqlcipher_decrypt.py decrypt phonebook.db "thekey"
  python3 sqlcipher_decrypt.py decrypt phonebook.db --raw a1b2...  --out out.sqlite
  python3 sqlcipher_decrypt.py batch ./dump "thekey"
  python3 sqlcipher_decrypt.py huntkey phonebook.db firmware.bin
"""
import sys, os, math, collections, contextlib, glob, re

# ---- SQLCipher parameter profiles, ordered most to least likely ----
PROFILES = [
    ("compat4 page4096 PBKDF2-256000 HMAC-SHA512",
        ["PRAGMA cipher_compatibility=4", "PRAGMA cipher_page_size=4096"]),
    ("compat3 page1024 PBKDF2-64000 HMAC-SHA1",
        ["PRAGMA cipher_compatibility=3"]),
    ("compat3 page4096",
        ["PRAGMA cipher_compatibility=3", "PRAGMA cipher_page_size=4096"]),
    ("compat2 page1024 PBKDF2-4000 HMAC-SHA1",
        ["PRAGMA cipher_compatibility=2"]),
    ("compat1 page1024 PBKDF2-4000 no-HMAC",
        ["PRAGMA cipher_compatibility=1"]),
    ("compat4 plaintext_header=32",
        ["PRAGMA cipher_compatibility=4", "PRAGMA cipher_page_size=4096",
         "PRAGMA cipher_plaintext_header_size=32"]),
]

@contextlib.contextmanager
def quiet():
    # SQLCipher prints "hmac check failed" to stderr on every wrong key.
    with open(os.devnull, "w") as dn:
        old = os.dup(2); os.dup2(dn.fileno(), 2)
        try: yield
        finally: os.dup2(old, 2); os.close(old)

def _keyexpr(key, raw):
    if raw: return "\"x'%s'\"" % key
    return "'%s'" % key.replace("'", "''")

def _try(path, key, raw, pragmas):
    import sqlcipher3
    con = None
    try:
        con = sqlcipher3.connect(path)
        cur = con.cursor()
        cur.execute("PRAGMA key=%s" % _keyexpr(key, raw))
        for p in pragmas: cur.execute(p)
        n = cur.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        con.close()
        return True, n, tables
    except Exception as e:
        if con:
            try: con.close()
            except Exception: pass
        return False, str(e)[:60], None

def find_profile(path, key, raw):
    with quiet():
        for name, pragmas in PROFILES:
            ok, info, tables = _try(path, key, raw, pragmas)
            if ok:
                return name, pragmas, info, tables
    return None

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b); L = len(b); e = 0.0
    for v in c.values():
        p = v / L; e -= p * math.log2(p)
    return e

def fingerprint(path):
    d = open(path, "rb").read(); n = len(d)
    ent = entropy(d)
    blocks = collections.Counter(d[i:i+16] for i in range(0, n-15, 16))
    reps = sum(1 for c in blocks.values() if c > 1)
    print("file:", path)
    print("size:", n, "bytes")
    print("  /1024:", "yes %d pages" % (n//1024) if n % 1024 == 0 else "no")
    print("  /4096:", "yes %d pages" % (n//4096) if n % 4096 == 0 else "no")
    print("entropy: %.4f bits/byte (8.0 = random)" % ent)
    print("salt (first 16 bytes):", d[:16].hex())
    print("repeated 16-byte blocks:", reps)
    if ent > 7.99 and reps == 0 and (n % 1024 == 0):
        print("verdict: MATCHES the SQLCipher/AES pattern of your phonebook.db")
    else:
        print("verdict: does NOT match (different scheme or not encrypted)")

def do_decrypt(path, key, raw, out=None):
    import sqlcipher3
    res = find_profile(path, key, raw)
    if not res:
        print("[-] key rejected under every known SQLCipher profile:", path)
        return False
    name, pragmas, info, tables = res
    out = out or (os.path.splitext(path)[0] + ".decrypted.sqlite")
    with quiet():
        con = sqlcipher3.connect(path); cur = con.cursor()
        cur.execute("PRAGMA key=%s" % _keyexpr(key, raw))
        for p in pragmas: cur.execute(p)
        if os.path.exists(out): os.remove(out)
        cur.execute("ATTACH DATABASE ? AS plain KEY ''", (out,))
        cur.execute("SELECT sqlcipher_export('plain')")
        cur.execute("DETACH DATABASE plain")
        con.close()
    print("[+] KEY WORKS  profile:", name)
    print("    tables:", tables)
    print("    wrote:", out)
    return True

DEFAULT_WORDS = ["", "phonebook","bosch","Bosch","BOSCH","nissan","Nissan",
    "rogue","Rogue","contacts","password","admin","root","default","0000",
    "1234","12345678","bluetooth","pbap","PBAP","infotainment","sqlcipher",
    "boschcarmultimedia","car","vehicle","connect","secret","key"]

def do_try(path, words=None):
    words = words or DEFAULT_WORDS
    print("[*] testing %d passphrases across %d profiles..." % (len(words), len(PROFILES)))
    for w in words:
        res = find_profile(path, w, False)
        if res:
            print("[+] HIT passphrase=%r profile=%s tables=%s" % (w, res[0], res[3]))
            return w
    print("[-] no weak/default key worked. Key must come from the unit firmware.")
    return None

def do_batch(folder, key, raw):
    files = []
    for ext in ("*.db","*.sqlite","*.sqlitedb","*.dat"):
        files += glob.glob(os.path.join(folder, "**", ext), recursive=True)
    print("[*] %d candidate files" % len(files))
    for f in sorted(set(files)):
        if entropy(open(f,"rb").read(4096)) > 7.9:
            do_decrypt(f, key, raw)

def do_huntkey(path, blob):
    data = open(blob, "rb").read()
    print("[*] scanning %s (%d bytes) for key candidates" % (blob, len(data)))
    cands = []
    # ascii key-like strings
    for m in set(re.findall(rb"[\x21-\x7e]{6,64}", data)):
        cands.append(("ascii", m.decode(errors="ignore"), False))
    # 32-byte high-entropy windows (raw AES-256 keys), sampled on 4-byte stride
    seen = set()
    for i in range(0, len(data)-32, 4):
        w = data[i:i+32]
        if w in seen: continue
        seen.add(w)
        if entropy(w) >= 4.2:
            cands.append(("raw32", w.hex(), True))
    print("[*] %d candidates, testing (ascii first)..." % len(cands))
    cands.sort(key=lambda c: c[0])  # ascii before raw32
    for i,(kind,val,raw) in enumerate(cands):
        res = find_profile(path, val, raw)
        if res:
            print("[+] KEY FOUND via %s: %s" % (kind, val))
            print("    profile:", res[0], "tables:", res[3])
            return val, raw
        if i % 2000 == 0 and i:
            print("    ...tested %d/%d" % (i, len(cands)))
    print("[-] no embedded key matched. Try a different firmware region or a Frida hook.")
    return None

def main():
    a = sys.argv
    if len(a) < 3:
        print(__doc__); return
    cmd = a[1]; path = a[2]
    raw = "--raw" in a
    out = a[a.index("--out")+1] if "--out" in a else None
    if cmd == "fingerprint": fingerprint(path)
    elif cmd == "try": do_try(path)
    elif cmd == "decrypt":
        rest = [x for x in a[3:] if x not in ("--raw",) and x != "--out" and x != out]
        key = rest[0]
        do_decrypt(path, key, raw, out)
    elif cmd == "batch":
        key = a[3]; do_batch(path, key, raw)
    elif cmd == "huntkey":
        do_huntkey(path, a[3])
    else:
        print("unknown command:", cmd); print(__doc__)

if __name__ == "__main__":
    main()
