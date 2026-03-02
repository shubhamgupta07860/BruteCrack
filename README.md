# 🔐 BruteCrack v2.0 — Advanced Hash Engine & Brute Force Tool

![Bash](https://img.shields.io/badge/Language-Bash-green?style=flat-square&logo=gnubash)
![Version](https://img.shields.io/badge/Version-2.0-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

> ⚠️ **Disclaimer:** This tool is intended **strictly for authorized penetration testing, CTF challenges, and educational purposes only.** Using this tool against systems you do not own or have explicit written permission to test is **illegal and unethical.** The author holds no responsibility for any misuse.

---

## 📖 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Supported Hash Algorithms](#-supported-hash-algorithms)
- [Installation](#-installation)
- [Usage](#-usage)
- [Examples](#-examples)
- [Screenshots](#-screenshots)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🧠 About

**BruteCrack** is a powerful, pure-Bash command-line tool built for penetration testers, CTF players, and cybersecurity students. It combines an advanced hash identification engine with brute force capabilities across multiple protocols — all in a single, dependency-light script.

Unlike other tools that require complex Python environments or compiled binaries, BruteCrack runs directly in your terminal using tools already available on most Linux/macOS systems (`openssl`, `md5sum`, `python3`).

---

## ✨ Features

- 🔍 **Advanced Hash Identification Engine**
  - Detects 40+ hash types from length, charset, and prefix patterns
  - Confidence scoring: HIGH / MEDIUM / LOW with reasons
  - Charset analysis: Hex, Base64, Modular Crypt Format (MCF), LDAP
  - Salted hash pattern detection (`hash:salt` format)
  - Top candidate highlighting with cracking recommendations

- 🔓 **Hash Cracking**
  - Wordlist-based dictionary attack
  - Auto-selects best algorithm(s) based on hash analysis
  - `--all-types` mode: tries every possible matching algorithm
  - Salt support with prepend/append positioning
  - Case-insensitive hash comparison

- 🌐 **Protocol Brute Force**
  - HTTP POST form login
  - SSH (via `sshpass`)
  - FTP

- 📄 **Output & Reporting**
  - Color-coded terminal output
  - Save results to file with `-o`
  - Clean, structured result summary on crack/find

---

## 🔑 Supported Hash Algorithms

| Category | Algorithms |
|---|---|
| **Standard** | MD2, MD4, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 |
| **SHA-3 / Keccak** | SHA-3-256, SHA-3-512, Keccak-224/256/384/512 |
| **BLAKE2** | BLAKE2b-512, BLAKE2s-256 |
| **Other** | RIPEMD-160, Whirlpool, Tiger-160/192, GOST R 34.11-94, Haval, Snefru, Skein |
| **Windows** | NTLM, LM Hash, DCC1, DCC2 (MS-Cache v2) |
| **MySQL** | MySQL 3.x (mysql323), MySQL 4.1/5+ (mysql41) |
| **Linux Shadow** | MD5Crypt (`$1$`), SHA-256 Crypt (`$5$`), SHA-512 Crypt (`$6$`) |
| **Web Frameworks** | bcrypt (`$2a/$2b/$2y`), WordPress PHPass (`$P$/$H$`), Apache APR1 |
| **Django** | PBKDF2-SHA256, PBKDF2-SHA1, SHA-1 |
| **Network Devices** | Cisco Type 7 (reversible), Cisco Type 8 (`$8$`), Juniper (`$9$`) |
| **LDAP** | `{SHA}`, `{SSHA}` (salted SHA-1), `{MD5}` |
| **Double Hash** | md5(md5()), sha1(sha1()), md5(sha1()), sha1(md5()) |
| **Base64 Encoded** | MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 |
| **Salted (auto)** | MD5:salt, SHA-1:salt, SHA-256:salt |

---

## ⚙️ Installation

### Prerequisites

```bash
# Debian / Ubuntu
sudo apt install curl openssl sshpass python3 xxd coreutils

# Arch Linux
sudo pacman -S curl openssl sshpass python xxd coreutils

# macOS (Homebrew)
brew install curl openssl sshpass python3
```

### Clone & Setup

```bash
git clone https://github.com/yourusername/brutecrack.git
cd brutecrack
chmod +x brutecrack.sh
```

---

## 🚀 Usage

```
./brutecrack.sh [MODE] [OPTIONS]

MODES:
  --identify     Identify hash type(s) only — no cracking
  --hash         Crack a hash using a wordlist
  --http-post    Brute force HTTP POST login form
  --ssh          Brute force SSH login
  --ftp          Brute force FTP login
  --help         Show help menu

GENERAL OPTIONS:
  -u <username>      Single username
  -w <wordlist>      Path to wordlist file
  -t <target>        Hash value, URL, or IP address
  -p <port>          Port override
  -f <fail-string>   String that appears on failed login
  -d <delay>         Delay (seconds) between attempts
  -o <file>          Save results to output file

HASH OPTIONS:
  --type <algo>      Force a specific algorithm
  --salt <value>     Salt value for salted hashes
  --salt-pos <pos>   append (default) | prepend
  --all-types        Try all matching algorithms automatically
```

---

## 📌 Examples

### 🔍 Identify a Hash

```bash
./brutecrack.sh --identify -t 5f4dcc3b5aa765d61d8327deb882cf99
```

### 💥 Crack a Hash (auto-detect algorithm)

```bash
./brutecrack.sh --hash -w /usr/share/wordlists/rockyou.txt -t 5f4dcc3b5aa765d61d8327deb882cf99
```

### 💥 Crack a Hash (try all matching algorithms)

```bash
./brutecrack.sh --hash -w rockyou.txt -t <hash> --all-types
```

### 💥 Crack a Hash (force specific algorithm)

```bash
./brutecrack.sh --hash -w rockyou.txt -t <hash> --type ntlm
```

### 🧂 Crack a Salted Hash

```bash
# Salt appended: password + salt
./brutecrack.sh --hash -w rockyou.txt -t <hash> --salt mysalt

# Salt prepended: salt + password
./brutecrack.sh --hash -w rockyou.txt -t <hash> --salt mysalt --salt-pos prepend
```

### 🌐 HTTP POST Brute Force

```bash
./brutecrack.sh --http-post -u admin -w rockyou.txt \
  -t http://target.local/login -f "Invalid credentials"
```

### 🔒 SSH Brute Force

```bash
./brutecrack.sh --ssh -u root -w passwords.txt -t 192.168.1.10
```

### 💾 Save Results to File

```bash
./brutecrack.sh --hash -w rockyou.txt -t <hash> --all-types -o results.txt
```

---

## 🗺️ Roadmap

- [ ] Multi-threading support (`xargs -P`) for faster attacks
- [ ] Proxy support for HTTP attacks (`--proxy`)
- [ ] Username list support for credential stuffing (`-U userlist.txt`)
- [ ] Rule-based wordlist mutations (append numbers, leet speak)
- [ ] bcrypt / Argon2 cracking support
- [ ] JSON output format for pipeline integration
- [ ] Auto-detect salt from `hash:salt` format

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

Please make sure your code follows the existing style and includes comments.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⭐ Star this repo if you found it useful!

> Built with ❤️ for the cybersecurity community.
