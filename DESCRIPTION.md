# BruteCrack — Project Description

## Short Description (GitHub "About" field — 1 line)

> A powerful Bash-based CLI tool for hash identification, hash cracking, and brute force attacks on HTTP, SSH, and FTP — built for ethical penetration testing and CTF challenges.

---

## Full Description

**BruteCrack** is an advanced, pure-Bash penetration testing tool that combines a smart hash identification engine with multi-protocol brute force capabilities. Designed for security professionals, CTF players, and cybersecurity students who want a lightweight, terminal-native toolkit without heavy dependencies.

### What makes BruteCrack different?

Most password auditing tools either require a complex Python environment, compiled binaries, or are locked to a single protocol. BruteCrack runs entirely in Bash using standard system utilities (`openssl`, `md5sum`, `python3`, `curl`) — making it portable, readable, and easy to customize.

### Core Capabilities

**Advanced Hash Identification Engine**
BruteCrack's hash identification engine detects over 40 hash types by analyzing hash length, character set, prefix patterns, and structural format. It goes well beyond simple length-based guessing — recognizing structured formats like bcrypt, Linux shadow hashes (`$1$`, `$5$`, `$6$`), Django password formats, LDAP-prefixed hashes, Cisco and Juniper device hashes, MySQL-specific algorithms, and Windows NTLM/LM hashes. Every identification includes a confidence rating (HIGH/MEDIUM/LOW), charset analysis, and a recommended cracking approach.

**Hash Cracking**
Once a hash is identified, BruteCrack performs a dictionary-based attack using any wordlist (e.g., rockyou.txt). It auto-selects the most probable algorithm, or with `--all-types`, systematically tries every matching algorithm. Salt support allows cracking of salted hashes with configurable salt position (prepend or append).

**Multi-Protocol Brute Force**
Beyond hash cracking, BruteCrack supports login brute force over HTTP POST forms, SSH, and FTP — all from the same unified CLI interface.

### Who is it for?

- Penetration testers performing authorized credential audits
- CTF players working on hash-cracking and login challenges
- Cybersecurity students learning how password hashing and brute force attacks work
- Developers testing the strength of their authentication implementations in lab environments

### Ethical Use

BruteCrack is built exclusively for authorized security testing. All usage must comply with applicable laws and regulations. Unauthorized use against systems you do not own is illegal.

---

## Tags / Topics (add these to your GitHub repo)

```
bash, cybersecurity, penetration-testing, hash-cracking, brute-force,
password-cracker, ctf, ethical-hacking, cli-tool, hash-identifier,
ntlm, md5, sha1, bcrypt, ssh-brute-force, ftp-brute-force, infosec
```
