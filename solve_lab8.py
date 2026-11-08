"""
Lab 8 - Breaking Salted Hashes (Challenge Lab)
Secure Communication and Cryptography - MACS H6014

Case: the Garda recovered a MySQL dump of password hashes from
www.exploringsecurity.com. The hashes are salted, with the same salt for
every user. Clues from the case file:
  * hashes are 40 hex chars  -> SHA-1
  * JavaScript revealed the format  CommonHash($salt, $pass)  -> SHA1(salt + pass)
  * the salt is "somewhere in our data (in this document)" -> the domain name
  * passwords set AFTER May 2010 : alphanumeric, 5-7 chars
  * passwords set BEFORE May 2010: digits only,  5-7 chars
Use the Pass_modified date of each row to pick the right policy.

Methods used:
  * digit accounts        -> brute force every 5-7 digit number
  * weak alpha accounts   -> dictionary of common passwords + the username
  * strong alpha accounts -> hashcat (GPU), mode 120 = SHA1($salt.$pass),
                             mask attack over the 5-7 char policy. The two
                             values hashcat returned are verified below against
                             the stored hashes so the whole result is reproducible.
"""
import hashlib, itertools

SALT = "www.exploringsecurity.com"          # salt found in the case document
sha1 = lambda s: hashlib.sha1(s.encode()).hexdigest()

# (username, hash, Pass_modified) straight from the dump table
DUMP = [
    ("Sparky",   "2834da08d58330d8dafbb2ac1c0f85f6b3b135ef", "2011-05-09"),
    ("Mark123",  "92e54f10103a3c511853c7098c04141f114719c1", "2010-06-03"),
    ("superman", "437fbc6892b38db6ac5bdbe2eab3f7bc924527d9", "2011-01-01"),
    ("security", "fafa4483874ec051989d53e1e432ba3a6c6b9143", "2010-01-11"),
    ("Tomtom",   "06f6fe0f73c6e197ee43eff4e5f7d10fb9e438b2", "2009-12-03"),
    ("JillC",    "f44f3b09df53c1c11273def13cacd8922a86d48c", "2010-12-20"),
]

# small dictionary for the alphanumeric accounts (common passwords + the username)
WORDLIST = ["password","qwerty","123456","letmein","superman","monkey","dragon",
            "shadow","master","football","abc123","iloveyou","trustno1","welcome"]

# passwords recovered with hashcat (GPU mask attack) for the two strong accounts
HASHCAT = {"Sparky": "Admin09", "JillC": "Q2w13sA"}

def digits_only(target):
    """brute force every 5-7 digit password."""
    for n in range(5, 8):
        for combo in itertools.product("0123456789", repeat=n):
            pw = "".join(combo)
            if sha1(SALT + pw) == target:
                return pw
    return None

def dictionary(target, extra):
    """try a small wordlist, plus the username itself, for alphanumeric accounts."""
    for pw in WORDLIST + [extra]:
        if 5 <= len(pw) <= 7 and sha1(SALT + pw) == target:
            return pw
    return None

def from_hashcat(user, target):
    """return the hashcat-recovered password, verified against the stored hash."""
    pw = HASHCAT.get(user)
    return pw if pw and sha1(SALT + pw) == target else None

print(f"Salt            : {SALT}")
print(f"Hash format     : SHA1(salt + password)\n")
print(f"{'Username':10}{'Policy':14}{'Password':12}{'Method'}")
print("-"*54)
for user, h, pmod in DUMP:
    after_may_2010 = pmod > "2010-05"
    policy = "alphanumeric" if after_may_2010 else "digits"
    if not after_may_2010:
        pw, method = digits_only(h), "digit brute force"
    else:
        pw = dictionary(h, user)
        method = "dictionary"
        if not pw:
            pw, method = from_hashcat(user, h), "hashcat (GPU mask)"
    print(f"{user:10}{policy:14}{(pw if pw else '(not cracked)'):12}{method}")
