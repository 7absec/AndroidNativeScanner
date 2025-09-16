#!/usr/bin/env python3
"""
android_native_scanner_nosuggest.py

Cross-platform Android native (.so) scanner — suggestions for objcopy removed.

Features:
 - Pure-Python ASCII + UTF-16LE string extraction with offsets (works on Windows/Linux/macOS).
 - Optional use of readelf/nm if present (no requirement).
 - Built-in sensitive & flag patterns (ignored if custom --search provided).
 - No objcopy/llvm-objcopy suggestion output anymore.
 - CLI: -s/--search (repeatable), -q/--silent, --save, -v/--verbose
"""

from __future__ import annotations
import os
import re
import sys
import json
import argparse
import base64
import subprocess
from shutil import which
from typing import List, Tuple, Optional, Dict, Set

# optional color
try:
    from termcolor import colored
except Exception:
    def colored(s, _col=None):
        return s

# ---------------- Patterns ----------------
SENSITIVE_AND_FLAG_PATTERNS = {
    # Keys / tokens
    "Google API Key": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    "OpenAI Key": re.compile(r"sk-(live|test)?-[0-9a-zA-Z]{32,48}"),
    "GitHub PAT (ghp_)": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "Stripe Secret Key": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,48}"),
    "Stripe Publishable Key": re.compile(r"pk_(live|test)_[0-9a-zA-Z]{24,48}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{8,}"),
    "AWS Access Key ID (AKIA/ASIA)": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS Secret (heuristic, 40 chars)": re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    "SendGrid API Key": re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    "Twilio SID (AC...)": re.compile(r"\bAC[0-9a-fA-F]{32}\b"),

    # JWT / Bearer
    "JWT": re.compile(r"\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"),
    "Bearer token (heuristic)": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-\._~\+\/=]{20,}\b"),

    # Credentials / passwords (heuristic)
    "Password/Token (heuristic)": re.compile(r"(?i)(pass(word)?|pwd|token|auth|secret)[\"'`:=\s]{0,6}[A-Za-z0-9_\-@#$%]{6,128}"),
    "BasicAuth (Base64) header": re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}\b"),
    "OAuth client_secret (param)": re.compile(r"(?i)client_secret[\"'\s:=]{0,6}[A-Za-z0-9\-_\./+=]{8,100}"),

    # PEM / certs
    "PEM RSA PRIVATE KEY": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    "PEM PRIVATE KEY": re.compile(r"-----BEGIN PRIVATE KEY-----"),
    "PEM ENCRYPTED PRIVATE KEY": re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    "PEM CERTIFICATE": re.compile(r"-----BEGIN CERTIFICATE-----"),

    # DB / Connection URIs
    "JDBC MySQL": re.compile(r"jdbc:mysql:\/\/[^\s'\";]+"),
    "MongoDB URI": re.compile(r"mongodb(?:\+srv)?:\/\/[^\s'\";]+"),
    "Postgres URI": re.compile(r"postgres(?:ql)?:\/\/[^\s'\";]+"),
    "Redis URL": re.compile(r"redis:\/\/[^\s'\";]+"),
    "RDS Endpoint (heuristic)": re.compile(r"[a-z0-9\-]+\.rds\.amazonaws\.com"),

    # URLs / internal hosts
    "Internal Hostname (heuristic)": re.compile(r"\b(?:internal|staging|dev|qa|backend|admin|internal-api)[\.\-][A-Za-z0-9\.\-]*", flags=re.IGNORECASE),
    "Private IP:Port (RFC1918)": re.compile(r"\b(?:(?:10|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3})(?::\d{2,5})?\b"),

    # Flags / CTFs
    "CTF Flag (CTF{...})": re.compile(r"CTF\{[A-Za-z0-9_!@\-\.\+]{1,256}\}"),
    "FLAG pattern (FLAG{...})": re.compile(r"FLAG\{[A-Za-z0-9_!@\-\.\+]{1,256}\}"),
    "Curly-braced token (heuristic)": re.compile(r"\b[A-Z0-9_]{3,20}\{[^\}]{3,300}\}"),

    # Misc
    "Email (heuristic)": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "S3 URL (heuristic)": re.compile(r"https?://s3[.-][a-z0-9-]+\.amazonaws\.com/[^\s'\"<>]+"),
    "API key in query (heuristic)": re.compile(r"[?&](api_key|key|token|auth)[=][A-Za-z0-9\-_\.%]{8,200}"),
}

# symbol-level RCE detection (only via nm if available)
RCE_SYMBOLS_RE = re.compile(
    r"\b(system|exec|popen|dlopen|dlsym|strcpy|sprintf|gets|scanf|memcpy|fopen|chmod|wget|curl|Runtime|loadLibrary)\b",
    flags=re.IGNORECASE
)

# scoring & thresholds
SCORES = {
    "sensitive": 6,   # high for keys
    "heuristic": 3,   # lower for heuristics
    "url": 1,
    "base64": 2,
    "jni": 1,
    "toolchain_url": 2,
    "custom": 2,
    "rce_symbol": 5,
}
THRESHOLD_HIGH = 15
THRESHOLD_MEDIUM = 7

# ---------------- Helpers ----------------
def run_cmd(cmd: List[str]) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout or ""
    except FileNotFoundError:
        return f"[ERROR_TOOL_MISSING] {' '.join(cmd)}"
    except subprocess.CalledProcessError as e:
        return f"[ERROR_CMD_FAIL] {' '.join(cmd)}\n{e.stderr or e.stdout or ''}"

def find_executable(names: List[str]) -> Optional[str]:
    for n in names:
        p = which(n)
        if p:
            return p
    return None

# ---------------- String extraction (pure Python) ----------------
ASCII_PRINTABLE = set(range(32, 127)) | {9, 10, 13}
UTF16_PATTERN = re.compile(b'(?:[ -~]\x00){4,}')  # sequences like A\x00B\x00...

def extract_ascii_strings_with_offsets(data: bytes, min_len: int = 4) -> List[Tuple[int, str]]:
    results = []
    cur_start = None
    cur_bytes = []
    for i, b in enumerate(data):
        if b in ASCII_PRINTABLE:
            if cur_start is None:
                cur_start = i
            cur_bytes.append(b)
        else:
            if cur_start is not None:
                if len(cur_bytes) >= min_len:
                    try:
                        s = bytes(cur_bytes).decode('utf-8', errors='replace')
                    except Exception:
                        s = ''.join(chr(c) for c in cur_bytes)
                    results.append((cur_start, s))
                cur_start = None
                cur_bytes = []
    if cur_start is not None and len(cur_bytes) >= min_len:
        try:
            s = bytes(cur_bytes).decode('utf-8', errors='replace')
        except Exception:
            s = ''.join(chr(c) for c in cur_bytes)
        results.append((cur_start, s))
    return results

def extract_utf16le_strings_with_offsets(data: bytes, min_chars: int = 4) -> List[Tuple[int, str]]:
    results = []
    for m in UTF16_PATTERN.finditer(data):
        start = m.start()
        raw = m.group(0)
        try:
            s = raw.decode('utf-16le', errors='replace')
        except Exception:
            continue
        if len(s) >= min_chars:
            results.append((start, s))
    return results

def extract_strings_from_file(so_path: str, min_len: int = 4) -> List[Tuple[int, str]]:
    with open(so_path, 'rb') as fh:
        data = fh.read()
    ascii_strings = extract_ascii_strings_with_offsets(data, min_len=min_len)
    utf16_strings = extract_utf16le_strings_with_offsets(data, min_chars=min_len)
    combined = { (off, val) for off, val in ascii_strings }
    combined.update({ (off, val) for off, val in utf16_strings })
    return sorted(combined, key=lambda t: t[0])

# ---------------- base64 detection ----------------
def is_printable_text(bs: bytes, min_print_pct: float = 0.6) -> bool:
    if not bs: return False
    printable = sum(1 for b in bs if b in ASCII_PRINTABLE)
    return (printable / len(bs)) >= min_print_pct

def detect_base64_strings(strings_list: List[str]) -> List[Tuple[str, str]]:
    found = []
    for s in strings_list:
        token = s.strip()
        if len(token) >= 24 and re.fullmatch(r'[A-Za-z0-9+/=]+', token):
            try:
                decoded = base64.b64decode(token, validate=True)
                if is_printable_text(decoded):
                    text = decoded.decode('utf-8', errors='replace')
                    found.append((token, text))
            except Exception:
                continue
    return found

# ---------------- Scanner ----------------
class Scanner:
    def __init__(self, silent: bool=False, save_path: Optional[str]=None, verbose: bool=False):
        self.silent = silent
        self.verbose = verbose
        self.save_path = save_path
        self._save_handle = open(save_path, 'w', encoding='utf-8') if save_path else None
        self.extractions: Dict[str, List[Dict]] = {}

    def close(self):
        if self._save_handle:
            self._save_handle.close()
            self._save_handle = None

    def _write_save(self, line: str):
        if self._save_handle:
            self._save_handle.write(re.sub(r'\x1b\[[0-9;]*m', '', line) + "\n")

    def _print(self, line: str, color: Optional[str]=None, match: bool=False):
        if self._save_handle:
            self._write_save(line)
        if not self.silent or match:
            try:
                if color:
                    print(colored(line, color))
                else:
                    print(line)
            except Exception:
                print(line)

    def analyze(self, so_path: str, custom_patterns: Optional[List[Tuple[str, re.Pattern, str]]] = None):
        if not os.path.isfile(so_path):
            self._print(f"[!] File not found: {so_path}", "red", match=True)
            return None

        self.extractions.setdefault(so_path, [])
        risk = 0
        matches_found = False

        self._print(f"[*] Android Native Scanner - Analyzing: {so_path}")

        # external tools (optional)
        readelf = find_executable(['readelf', 'readelf.exe'])
        nm_exec = find_executable(['nm', 'nm.exe'])

        # readelf header
        if readelf:
            elf_hdr = run_cmd([readelf, '-h', so_path])
            if elf_hdr.startswith("[ERROR_"):
                self._print(f"[!] readelf error: {elf_hdr}", "yellow", match=True)
            else:
                self._print("[+] ELF Header:")
                if self.verbose:
                    self._print(elf_hdr)
                else:
                    summary = []
                    for ln in elf_hdr.splitlines():
                        if any(k in ln for k in ("Class:", "Data:", "Entry point address:", "OS/ABI:")):
                            summary.append(ln)
                    self._print("\n".join(summary))
        else:
            self._print("[!] readelf not found on PATH — skipping ELF header (optional).", "yellow")

        # nm symbols
        nm_out = ""
        if nm_exec:
            nm_out = run_cmd([nm_exec, '-D', so_path])
            if nm_out.startswith("[ERROR_"):
                self._print(f"[!] nm error: {nm_out}", "yellow")
                nm_out = ""
            else:
                if self.verbose:
                    self._print("\n[+] Exported symbols (nm -D):")
                    self._print(nm_out)
                else:
                    self._print("[+] Exported symbols parsed (use --verbose to dump full table)")
        else:
            self._print("[!] nm not found on PATH — symbol-based RCE checks will be skipped.", "yellow")

        # RCE symbol checks (only if nm produced output)
        if nm_out:
            self._print("\n[+] RCE-related symbols (nm):")
            rce_syms = []
            for ln in nm_out.splitlines():
                if RCE_SYMBOLS_RE.search(ln):
                    rce_syms.append(ln.strip())
            if rce_syms:
                for s in sorted(set(rce_syms)):
                    self._print(f"[*] {s}", "red", match=True)
                    risk += SCORES['rce_symbol']
                    matches_found = True
            else:
                self._print("[-] No suspicious RCE symbols found.")

        # extract strings with offsets
        strings_with_offsets = extract_strings_from_file(so_path, min_len=4)
        strings_list = [txt for (_, txt) in strings_with_offsets]

        # .comment / .note via readelf if available
        combined_comment = ""
        if readelf:
            comment = run_cmd([readelf, '-p', '.comment', so_path])
            note = run_cmd([readelf, '-p', '.note', so_path])
            combined_comment = "\n".join([x for x in (comment, note) if x and not x.startswith("[ERROR_")])
        toolchain_urls: Set[str] = set()
        if combined_comment:
            self._print("\n[+] .comment/.note contents:")
            self._print(combined_comment)
            toolchain_urls = set(re.findall(r"https?://[^\s\"'>]+", combined_comment))
            for u in toolchain_urls:
                self._print(f"[*] Toolchain URL: {u}", "yellow", match=True)
                risk += SCORES['toolchain_url']
                matches_found = True

        # Decide which patterns to use:
        if custom_patterns:
            self._print("\n[+] Running in CUSTOM mode: only user-supplied patterns will be searched.")
        else:
            self._print("\n[+] Running in DEFAULT mode: using built-in sensitive & flag patterns.")

        # Search patterns
        if custom_patterns:
            self._print("\n[+] Custom patterns check:")
            any_hit = False
            for label, pat, raw in custom_patterns:
                for idx, s in enumerate(strings_list):
                    if pat.search(s):
                        off = strings_with_offsets[idx][0] if idx < len(strings_with_offsets) else -1
                        off_str = f" (offset=0x{off:x})" if off and off >= 0 else ""
                        self._print(f"[+] Custom '{raw}': {s}{off_str}", "green", match=True)
                        risk += SCORES['custom']
                        any_hit = True
                        matches_found = True
                        self.extractions[so_path].append({"type": f"custom:{raw}", "value": s, "offset": off if off and off >= 0 else None})
            if not any_hit:
                self._print("[-] No matches for provided custom patterns.")
        else:
            self._print("\n[+] Built-in sensitive & flag patterns:")
            found = []
            for idx, s in enumerate(strings_list):
                for label, pat in SENSITIVE_AND_FLAG_PATTERNS.items():
                    if pat.search(s):
                        off = strings_with_offsets[idx][0] if idx < len(strings_with_offsets) else -1
                        found.append((label, s, off))
            if found:
                for label, val, off in sorted(set(found)):
                    color = "green" if "Key" in label or "Token" in label or "SECRET" in label.upper() else "cyan"
                    off_str = f" (offset=0x{off:x})" if off is not None and off >= 0 else ""
                    self._print(f"[!] {label}: {val}{off_str}", color, match=True)
                    if any(k in label.lower() for k in ("key", "token", "secret", "private", "jwt")):
                        risk += SCORES['sensitive']
                    else:
                        risk += SCORES['heuristic']
                    matches_found = True
                    self.extractions[so_path].append({"type": label, "value": val, "offset": off if off and off >= 0 else None})
            else:
                self._print("[-] No built-in sensitive/flag patterns found.")

        # URLs found in strings (exclude toolchain URLs)
        self._print("\n[+] Hardcoded URLs (strings):")
        url_set = set(re.findall(r"https?://[^\s\"'>]+", "\n".join(strings_list)))
        user_urls = sorted(url_set - toolchain_urls)
        if user_urls:
            for u in user_urls:
                self._print(f"[*] URL: {u}", "green", match=True)
                risk += SCORES['url']
                matches_found = True
                self.extractions[so_path].append({"type": "URL", "value": u, "offset": None})
        else:
            self._print("[-] No user-facing URLs found in strings (besides .comment/.note).")

        # Base64 detection
        self._print("\n[+] Base64-like strings (decoded heuristics):")
        b64s = detect_base64_strings(strings_list)
        if b64s:
            for orig, dec in b64s:
                off = next((o for (o, t) in strings_with_offsets if t == orig), None)
                off_str = f" (offset=0x{off:x})" if off is not None and off >= 0 else ""
                snippet = dec[:300].replace("\n", "\\n")
                self._print(f"[*] Encoded: {orig}{off_str}\n    → Decoded (snippet): {snippet}", "magenta", match=True)
                risk += SCORES['base64']
                matches_found = True
                self.extractions[so_path].append({"type": "base64", "value": orig, "decoded": dec, "offset": off if off and off >= 0 else None})
        else:
            self._print("[-] No likely base64-encoded text discovered.")

        # JNI methods
        self._print("\n[+] JNI Methods (Java_ prefixes):")
        jni_hits = []
        for idx, s in enumerate(strings_list):
            if re.search(r"Java_[A-Za-z0-9_]+", s):
                off = strings_with_offsets[idx][0] if idx < len(strings_with_offsets) else -1
                jni_hits.append((s, off))
        if jni_hits:
            for s, off in sorted(set(jni_hits)):
                off_str = f" (offset=0x{off:x})" if off and off >= 0 else ""
                self._print(f"[*] {s}{off_str}", "cyan", match=True)
                risk += SCORES['jni']
                matches_found = True
                self.extractions[so_path].append({"type": "JNI", "value": s, "offset": off if off and off >= 0 else None})
        else:
            self._print("[-] No JNI signatures found in strings.")

        # final scoring & summary
        self._print(f"\n[+] Final Risk Score: {risk}")
        if risk >= THRESHOLD_HIGH:
            self._print("[!] Risk Level: HIGH ⚠️", "red", match=True)
        elif risk >= THRESHOLD_MEDIUM:
            self._print("[!] Risk Level: MEDIUM ⚠", "yellow", match=True)
        else:
            self._print("[+] Risk Level: LOW ✅", "green", match=matches_found)

        self._print("\n[✓] Analysis complete.")
        return {"path": so_path, "risk": risk, "matches_found": matches_found}

# ---------------- CLI helpers ----------------
def load_custom_patterns(tokens: Optional[List[str]]) -> List[Tuple[str, re.Pattern, str]]:
    patterns: List[Tuple[str, re.Pattern, str]] = []
    if not tokens:
        return patterns
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        raw = token
        label = token
        if token.startswith("re:"):
            try:
                pat = re.compile(token[3:])
            except re.error:
                print(f"[!] Invalid regex provided, skipping: {token}", file=sys.stderr)
                continue
            patterns.append((label, pat, raw))
        else:
            patterns.append((label, re.compile(re.escape(token)), raw))
    return patterns

def main():
    print("Android Native Scanner v1.0")
    print("Author: 7absec \n")
    parser = argparse.ArgumentParser(description="Android native .so scanner (no objcopy suggestions)")
    parser.add_argument("path", help="Path to .so file or directory containing .so files")
    parser.add_argument("-s", "--search", action="append", help="Custom search pattern (plain or 're:<regex>'), repeatable. If provided, defaults are ignored.")
    parser.add_argument("-q", "--silent", action="store_true", help="Silent mode: only print matches")
    parser.add_argument("--save", metavar="FILE", help="Save human-readable report to FILE")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode: dump full external tool output if present")
    args = parser.parse_args()

    custom_patterns = load_custom_patterns(args.search)
    scanner = Scanner(silent=args.silent, save_path=args.save, verbose=args.verbose)

    results = []
    try:
        if os.path.isdir(args.path):
            for root, _, files in os.walk(args.path):
                for fn in files:
                    if fn.endswith(".so"):
                        res = scanner.analyze(os.path.join(root, fn), custom_patterns if custom_patterns else None)
                        if res:
                            results.append(res)
        else:
            res = scanner.analyze(args.path, custom_patterns if custom_patterns else None)
            if res:
                results.append(res)
    finally:
        scanner.close()

    highest = max((r["risk"] for r in results if r), default=0)
    if highest >= THRESHOLD_HIGH:
        sys.exit(2)
    elif highest >= THRESHOLD_MEDIUM:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
