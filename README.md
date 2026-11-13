# sqlcipher-decrypt-toolkit

Command line toolkit for SQLCipher encrypted SQLite files from automotive
and embedded systems. Built first for a Bosch head unit phonebook from a
2025 Nissan Rogue, and written to work on any file that uses the same
encryption.

Many car infotainment units, phones, and apps store contacts, call logs,
and messages in SQLite, then lock the file with SQLCipher (AES-256). The
database body is unreadable without the key. This tool identifies such a
file, tests it, and decrypts it once you supply the key.

## What it does

- `fingerprint` Confirm a file uses SQLCipher style encryption.
- `try` Test a built in list of weak and default passphrases.
- `decrypt` Decrypt one file with a key you supply. Auto detects the
  SQLCipher parameter profile and writes a plain `.sqlite`.
- `batch` Decrypt every matching file in a folder with one key.
- `huntkey` Scan a firmware dump or binary for candidate keys and test
  each one against the database automatically.

## Install

```
pip install -r requirements.txt
```

Needs Python 3.8 or newer.

## Use

```
# confirm the encryption type
python3 sqlcipher_decrypt.py fingerprint phonebook.db

# quick test of weak and default keys
python3 sqlcipher_decrypt.py try phonebook.db

# decrypt with a passphrase
python3 sqlcipher_decrypt.py decrypt phonebook.db "THEKEY"

# decrypt with a raw 32 byte key (64 hex chars)
python3 sqlcipher_decrypt.py decrypt phonebook.db --raw <64hex> --out out.sqlite

# decrypt a whole folder with one key
python3 sqlcipher_decrypt.py batch ./extracted "THEKEY"

# find the key inside a firmware image and auto decrypt on a hit
python3 sqlcipher_decrypt.py huntkey phonebook.db firmware.bin
```

Open the output `.sqlite` in DB Browser for SQLite or the `sqlite3` CLI.

## How SQLCipher protects the file

The database is AES-256. The first 16 bytes are the key salt. SQLCipher
derives the AES key from your passphrase and that salt with PBKDF2. There
is no shortcut around this. You need the key.

The key is never stored in the database. On an embedded unit it lives in
the firmware. Two ways to recover it:

1. Firmware dump. Pull the unit image, then run `huntkey` against it.
2. Live hook. If you reach a shell on the unit, attach Frida and hook
   `sqlite3_key`. The key passes through in the clear when the database
   opens. This is the method automotive forensic tools use.

## Key formats

- Passphrase. Plain text. SQLCipher runs PBKDF2 to get the AES key.
- Raw key. Exactly 64 hex characters, passed with `--raw`. Use this when
  the firmware stores the derived key directly.

## Supported profiles

The tool auto detects SQLCipher compatibility 1 through 4, page size 1024
and 4096, and a plaintext header variant. Add more in the `PROFILES` list
at the top of the script.

## Scope and ethics

Use this on devices and data you own or are authorized to examine. This is
a right to repair and personal data recovery tool. The `.gitignore` keeps
recovered databases, keys, and firmware out of the repo. Do not commit
them.

## License

MIT. See LICENSE.
