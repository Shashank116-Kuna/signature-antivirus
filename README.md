# Basic Antivirus Simulation — Signature-Based Hash Scanner

> **Disclaimer:** This project is strictly for **educational purposes only**.
> It does **not** detect real-world malware unless genuine malware SHA-256
> signatures are manually added to `signatures.txt`.
> Never scan systems you do not own or have explicit written permission to test.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [File Structure](#2-file-structure)
3. [How It Works](#3-how-it-works)
4. [System Flowchart](#4-system-flowchart-text-based)
5. [Getting Started](#5-getting-started)
6. [signatures.txt Format](#6-signaturestxt-format)
7. [Sample Output](#7-sample-output)
8. [Code Architecture](#8-code-architecture)
9. [Suggested Improvements](#9-suggested-improvements)
10. [Ethical & Legal Notice](#10-ethical--legal-notice)

---

## 1. Project Overview

This Python project simulates the core mechanism behind a **signature-based
antivirus engine** — the same fundamental approach used by commercial products
like Windows Defender, ClamAV, and McAfee.

| Feature | Detail |
|---|---|
| Language | Python 3.x (standard library only) |
| Detection method | SHA-256 file hash comparison |
| Scan scope | Recursive (all files in a folder and sub-folders) |
| On detection | File is moved to a quarantine folder |
| Reporting | Console output + `scan_log.txt` with timestamps |

---

## 2. File Structure

```
antivirus_sim/
│
├── antivirus.py        ← Main scanner (all logic lives here)
├── signatures.txt      ← Malware hash database (one SHA-256 per line)
├── scan_log.txt        ← Auto-generated audit log (created at runtime)
│
└── quarantine/         ← Auto-created folder; infected files land here
```

---

## 3. How It Works

### Step-by-step walkthrough

**Step 1 — Load signatures**
The scanner reads `signatures.txt` line-by-line, strips comments and blank
lines, validates that each entry is a 64-character hex string, and stores all
hashes in a Python `set` for O(1) lookup speed.

**Step 2 — Collect files**
`os.walk()` recursively traverses the target directory, building a list of
every file path. The quarantine folder itself is excluded so already-flagged
files are never re-scanned.

**Step 3 — Hash each file**
For every file, `hashlib.sha256()` reads the file in 64 KB chunks and
produces a 64-character hexadecimal digest. Chunked reading ensures the
scanner can handle files of any size without loading them fully into RAM.

**Step 4 — Signature comparison**
The computed hash is looked up in the in-memory signature set. A match means
the file's fingerprint is identical to a known malicious file — this is called
a **hash collision with the malware database**.

**Step 5 — Quarantine**
Matched files are moved (not copied) to the `quarantine/` folder using
`shutil.move()`. If a file with the same name already exists in quarantine,
a timestamp suffix prevents overwriting.

**Step 6 — Log & report**
Every event is written to `scan_log.txt` with a timestamp. After the scan
completes, a formatted summary is printed to the console and appended to the
log.

---

## 4. System Flowchart (Text-Based)

```
┌─────────────────────────────────────────────┐
│               PROGRAM START                 │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│   Print banner & prompt user for folder     │
│   path. Validate that it is a real          │
│   directory; re-prompt if not.              │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│   load_signatures(signatures.txt)           │
│   • Read each line                          │
│   • Skip comments (#) and blank lines       │
│   • Validate 64-char hex format             │
│   • Store in a Python set                   │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│   gather_files(scan_dir)                    │
│   • os.walk() the target directory          │
│   • Skip the quarantine sub-folder          │
│   • Return sorted list of file paths        │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
                 ┌─────┴─────┐
                 │ files list │
                 └─────┬─────┘
                       │
          ┌────────────▼────────────┐
          │  For each file in list  │◄──────────────────┐
          └────────────┬────────────┘                   │
                       │                                │
                       ▼                                │
          ┌─────────────────────────┐                   │
          │  compute_sha256(file)   │                   │
          │  Read in 64KB chunks    │                   │
          └────────────┬────────────┘                   │
                       │                                │
              ┌────────▼────────┐                       │
              │  Hash computed? │                       │
              └───┬────────┬────┘                       │
                  │ NO     │ YES                        │
                  ▼        ▼                            │
             [SKIP +   ┌──────────────────────┐        │
             log err]  │ hash IN signatures?  │        │
                       └──────┬───────┬───────┘        │
                              │ YES   │ NO              │
                              ▼       ▼                 │
                    ┌──────────────┐ ┌───────────────┐  │
                    │ THREAT FOUND │ │  Mark as CLEAN │  │
                    │ quarantine() │ └───────────────┘  │
                    │ log THREAT   │                    │
                    └──────────────┘                    │
                                                        │
                       └────────────────────────────────┘
                              (next file)

                       │  (all files processed)
                       ▼
          ┌─────────────────────────────┐
          │   print_summary(results)    │
          │   • Total / Infected / Clean│
          │   • Elapsed time            │
          │   • Quarantined file list   │
          └─────────────────────────────┘
                       │
                       ▼
          ┌─────────────────────────────┐
          │   Append summary to         │
          │   scan_log.txt              │
          └─────────────────────────────┘
                       │
                       ▼
               ┌───────────────┐
               │  PROGRAM END  │
               └───────────────┘
```

---

## 5. Getting Started

### Prerequisites
- Python 3.8 or higher
- No third-party packages required

### Running the scanner

```bash
# 1. Clone / download the project folder
cd antivirus_sim

# 2. (Optional) Add test signatures — see Section 6

# 3. Run the scanner
python antivirus.py

# 4. When prompted, enter the full path to the folder you want to scan:
#    Enter the full path of the folder to scan: /home/user/documents
```

### Quick self-test (Linux/macOS)

```bash
# Create a harmless test file
echo "test payload" > /tmp/test_file.txt

# Compute its hash
sha256sum /tmp/test_file.txt
# Example output: a1b2c3...64chars...  /tmp/test_file.txt

# Paste that hash into signatures.txt, then scan /tmp
python antivirus.py
# → The scanner should flag and quarantine test_file.txt
```

### Quick self-test (Windows PowerShell)

```powershell
# Create a harmless test file
"test payload" | Out-File C:\Temp\test_file.txt -Encoding ASCII

# Compute its hash
Get-FileHash C:\Temp\test_file.txt -Algorithm SHA256

# Paste the hash into signatures.txt, then scan C:\Temp
python antivirus.py
```

---

## 6. signatures.txt Format

```
# This is a comment — ignored by the scanner
# Blank lines are also ignored

# FakeTrojan.Win32 — fictional test hash
aabbcc1122334455aabbcc1122334455aabbcc1122334455aabbcc1122334455

# AnotherSample — fictional test hash
deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

**Rules:**
- Each signature must be exactly **64 hexadecimal characters** (a full SHA-256 digest).
- Lines beginning with `#` are comments.
- Hashes are case-insensitive.
- Invalid lines are skipped with a warning logged.

To obtain **real** signatures for research, consult:
- [MalwareBazaar](https://bazaar.abuse.ch/) — public malware hash repository
- [VirusTotal](https://www.virustotal.com/) — hash lookup service
- [MISP](https://www.misp-project.org/) — threat intelligence sharing

---

## 7. Sample Output

```
╔══════════════════════════════════════════════════════════════════════╗
║       Basic Antivirus Simulation — SHA-256 Signature Scanner        ║
║                  [ EDUCATIONAL PURPOSE ONLY ]                       ║
║  This tool does NOT detect real malware without real signatures.    ║
╚══════════════════════════════════════════════════════════════════════╝

Enter the full path of the folder to scan: /home/user/test_folder

[2025-01-15 14:23:01] [INFO  ] Loaded 6 signature(s) from 'signatures.txt'.
[2025-01-15 14:23:01] [INFO  ] Starting scan of 4 file(s) in '/home/user/test_folder' ...
[2025-01-15 14:23:01] [INFO  ] ----------------------------------------------------------------------
[2025-01-15 14:23:01] [INFO  ] [   1/4] Scanning: /home/user/test_folder/readme.txt
[2025-01-15 14:23:01] [INFO  ] [   2/4] Scanning: /home/user/test_folder/photo.jpg
[2025-01-15 14:23:01] [INFO  ] [   3/4] Scanning: /home/user/test_folder/malware_test.exe
[2025-01-15 14:23:01] [THREAT] *** THREAT DETECTED ***  Hash: deadbeef...
[2025-01-15 14:23:01] [THREAT]     File: '/home/user/test_folder/malware_test.exe'
[2025-01-15 14:23:01] [INFO  ] Quarantined: '...malware_test.exe' → 'quarantine/malware_test.exe'
[2025-01-15 14:23:01] [INFO  ] [   4/4] Scanning: /home/user/test_folder/notes.docx

======================================================================
  SCAN COMPLETE – SUMMARY REPORT
======================================================================
  Target Directory : /home/user/test_folder
  Scan Duration    : 0.04 seconds
  Total Files Found: 4
  Files Scanned    : 4
  Files Skipped    : 0  (read errors / no permission)
  Clean Files      : 3
  Infected Files   : 1
======================================================================
  INFECTED FILES QUARANTINED:
    • /home/user/test_folder/malware_test.exe
      SHA-256: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
======================================================================
  Log saved to : /home/user/antivirus_sim/scan_log.txt
======================================================================
```

---

## 8. Code Architecture

| Function | Responsibility |
|---|---|
| `main()` | Entry point; orchestrates the full scan pipeline |
| `log()` | Unified logging to console and `scan_log.txt` |
| `load_signatures()` | Parses `signatures.txt` into a `set` |
| `compute_sha256()` | Hashes a single file in 64 KB chunks |
| `gather_files()` | Recursively walks directory; returns file list |
| `scan_directory()` | Core loop; hashes files, checks signatures, quarantines |
| `quarantine_file()` | Safely moves flagged file with collision handling |
| `print_summary()` | Formats and outputs the final scan report |

---

## 9. Suggested Improvements

### Near-term enhancements (beginner–intermediate)

| # | Improvement | Why |
|---|---|---|
| 1 | **Add a GUI** (Tkinter or PyQt) | Improves usability; folder picker instead of typed paths |
| 2 | **YARA rule support** | Real AV engines use pattern-matching beyond exact hashes |
| 3 | **File-type filtering** | Only scan `.exe`, `.dll`, `.js`, `.bat` to save time |
| 4 | **Restore from quarantine** | Let users un-quarantine false positives |
| 5 | **Scheduled scans** | Use `schedule` library or OS task scheduler |

### Intermediate enhancements

| # | Improvement | Why |
|---|---|---|
| 6 | **Online signature updates** | Fetch latest hashes from a threat feed URL |
| 7 | **Heuristic analysis** | Flag files with suspicious entropy or PE headers |
| 8 | **Multi-threading** | `concurrent.futures.ThreadPoolExecutor` for faster scans |
| 9 | **SQLite signature DB** | Faster lookups; supports metadata (malware family, date added) |
| 10 | **HTML report generation** | Produce a shareable scan report |

### Advanced enhancements (real-world AV concepts)

| # | Improvement | Why |
|---|---|---|
| 11 | **Fuzzy hashing (ssdeep)** | Detect near-identical malware variants |
| 12 | **Sandbox integration** | Execute suspicious files in isolation and observe behaviour |
| 13 | **Machine-learning classifier** | Train on PE header features to catch unknown malware |
| 14 | **Real-time file monitoring** | Use `watchdog` to scan files as they are created |
| 15 | **Encrypted quarantine vault** | Prevent quarantined malware from being re-executed |

---

## 10. Ethical & Legal Notice

```
╔══════════════════════════════════════════════════════════════════════╗
║                    ETHICAL & LEGAL NOTICE                           ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  1. This tool is built for LEARNING and DEMONSTRATION ONLY.         ║
║                                                                      ║
║  2. It does NOT detect real malware unless genuine SHA-256           ║
║     signatures of real malicious files are added to                  ║
║     signatures.txt.                                                  ║
║                                                                      ║
║  3. Always obtain WRITTEN PERMISSION before scanning any system      ║
║     that you do not personally own.                                  ║
║                                                                      ║
║  4. Do NOT use this tool to scan government, corporate, or third-    ║
║     party systems without authorisation. Doing so may violate the   ║
║     Computer Fraud and Abuse Act (USA), Computer Misuse Act (UK),   ║
║     or equivalent laws in your jurisdiction.                         ║
║                                                                      ║
║  5. The fictional hashes in signatures.txt are safe test values      ║
║     that will not match any real file unless you deliberately craft  ║
║     a test file whose hash you have added.                           ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

*Project built with Python standard library only — `os`, `hashlib`, `shutil`, `datetime`.*
