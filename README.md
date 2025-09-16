# Android Native Scanner

**Android native library scanner** for `.so` files.  
This tool extracts strings, scans for **sensitive data, API keys, tokens, CTF flags**, base64-encoded secrets, and JNI methods. It also supports **custom regex search**.

---

## Features

- **Pure-Python string extraction:** ASCII + UTF-16LE with offsets.
- **Optional external tools:** `readelf` and `nm` integration (if available).
- **Sensitive patterns:** Detect Google API keys, OpenAI keys, GitHub tokens, AWS secrets, JWTs, passwords, PEM keys, database URIs, internal hosts, and more.
- **CTF/flag detection:** Detect `CTF{}` and `FLAG{}` patterns.
- **Base64 detection:** Auto-decode likely base64 strings.
- **Custom search:** Supply your own string or regex patterns (overrides default patterns).
- **Silent mode:** Print only matches.
- **Save output:** Optionally save results to a file.
- **No external modifications:** Removed suggestions for `objcopy` or section removal.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/7absec/AndroidNativeScanner.git
cd AndroidNativeScanner
```

Install dependencies (optional, for colored output):

```bash
pip install termcolor
```

---

## Usage

### Scan a single `.so` file with default patterns

### Default Mode
Using built-in sensitive and flag patterns:
```bash
python NativeScanner.py path/to/lib***.so
```
![Default Mode](https://github.com/7absec/AndroidNativeScanner/blob/main/Default_mode.png)

### Scan a directory recursively

```bash
python NativeScanner.py path/to/libs/
```

### Custom Mode
Using user-supplied search patterns:

```bash
# Plain string search
python NativeScanner.py libnativeflag.so -s "CTF{"

# Regex search
python NativeScanner.py libnativeflag.so -s "re:CTF\{[A-Za-z0-9_!@\-\.\+]{1,256}\}"
```
![Custom Mode](https://github.com/7absec/AndroidNativeScanner/blob/main/Custom_mode.png)

> If custom search is provided, default patterns are ignored.

### Silent mode (only print matches)

```bash
python NativeScanner.py libnativeflag.so -q
```

### Save output to a file

```bash
python NativeScanner.py libnativeflag.so --save report.txt
```

### Verbose mode (full external tool output)

```bash
python NativeScanner.py libnativeflag.so -v
```

---

## Arguments

| Argument | Description |
|----------|-------------|
| `path` | Path to a `.so` file or directory containing `.so` files. |
| `-s, --search` | Custom search pattern. Can be repeated. Use `re:` prefix for regex. Overrides default patterns. |
| `-q, --silent` | Silent mode: print only matches. |
| `--save FILE` | Save human-readable report to `FILE`. |
| `-v, --verbose` | Verbose mode: prints full external tool output if available. |

---

## Example Output

```text
[*] Analyzing: libnativeflag.so
[!] CTF Flag: CTF{Android_Native_Hakure} (offset=0x1234)
[*] Base64: SGVsbG8gd29ybGQ= (offset=0x5678)
    → Decoded (snippet): Hello world
[-] No other matches found.
```

---

## Contributing

Feel free to open issues or submit pull requests. Future plans include:  

- Raw binary pattern search.  
- Automatic risk scoring and reporting.  
- Extended CTF/flag heuristics.

---

## License

MIT License
