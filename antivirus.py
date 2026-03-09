"""
=============================================================================
  Basic Antivirus Simulation - Signature-Based Hash Scanner
=============================================================================
  Author      : Cybersecurity Project (Educational Use Only)
  Language    : Python 3.x (Standard Library Only)
  Description : Simulates a basic antivirus scanner by computing SHA-256
                hashes of files and comparing them against a known malware
                signature database. Infected files are quarantined.

  DISCLAIMER  : This tool does NOT detect real-world malware unless actual
                malware SHA-256 hashes are loaded into signatures.txt.
                This project is strictly for EDUCATIONAL PURPOSES ONLY.
=============================================================================
"""

import os
import hashlib
import shutil
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION  (edit these paths to customise behaviour)
# ─────────────────────────────────────────────────────────────────────────────
SIGNATURES_FILE = "signatures.txt"   # File containing known malware hashes
QUARANTINE_DIR  = "quarantine"        # Folder where infected files are moved
LOG_FILE        = "scan_log.txt"      # Audit log with timestamps


# ─────────────────────────────────────────────────────────────────────────────
#  UTILITY: Logging
# ─────────────────────────────────────────────────────────────────────────────

def log(message: str, level: str = "INFO") -> None:
    """
    Write a timestamped log entry to scan_log.txt and print to the console.

    Parameters
    ----------
    message : str   The human-readable log message.
    level   : str   Severity label – INFO, WARN, THREAT, or ERROR.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [{level:<6}] {message}"

    # Always print to console
    print(entry)

    # Append to the log file (create if absent)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(entry + "\n")
    except OSError as exc:
        print(f"[WARNING] Could not write to log file: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 1: Load the malware signature database
# ─────────────────────────────────────────────────────────────────────────────

def load_signatures(sig_path: str) -> set:
    """
    Parse the signatures file and return a set of known malware SHA-256 hashes.

    The signatures file format (one hash per line, comments start with '#'):
        # This is a comment
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        ...

    Parameters
    ----------
    sig_path : str  Path to the signatures.txt file.

    Returns
    -------
    set  A set of lower-cased SHA-256 hash strings.
    """
    signatures = set()

    if not os.path.isfile(sig_path):
        log(f"Signature file not found: '{sig_path}'. Scanning with empty database.", "WARN")
        return signatures

    try:
        with open(sig_path, "r", encoding="utf-8") as sig_file:
            for raw_line in sig_file:
                line = raw_line.strip()
                # Skip blank lines and comment lines
                if not line or line.startswith("#"):
                    continue
                # A SHA-256 hash is exactly 64 hex characters
                if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
                    signatures.add(line.lower())
                else:
                    log(f"Skipping malformed signature entry: '{line}'", "WARN")
    except OSError as exc:
        log(f"Could not read signature file: {exc}", "ERROR")

    log(f"Loaded {len(signatures)} signature(s) from '{sig_path}'.")
    return signatures


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 2: Hash a single file with SHA-256
# ─────────────────────────────────────────────────────────────────────────────

def compute_sha256(file_path: str) -> str | None:
    """
    Compute and return the SHA-256 hash of a file.

    Reads the file in 64 KB chunks to keep memory usage low, which is
    important when scanning large files.

    Parameters
    ----------
    file_path : str  Absolute or relative path to the target file.

    Returns
    -------
    str | None  Lowercase hex digest on success; None on any read error.
    """
    hasher = hashlib.sha256()
    chunk_size = 65536  # 64 KB per read – efficient for large files

    try:
        with open(file_path, "rb") as target_file:
            while True:
                chunk = target_file.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except PermissionError:
        log(f"Permission denied – cannot read: '{file_path}'", "ERROR")
    except FileNotFoundError:
        log(f"File disappeared during scan: '{file_path}'", "ERROR")
    except OSError as exc:
        log(f"OS error reading '{file_path}': {exc}", "ERROR")

    return None  # Signal that hashing failed


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 3: Quarantine an infected file
# ─────────────────────────────────────────────────────────────────────────────

def quarantine_file(file_path: str, quarantine_dir: str) -> bool:
    """
    Move an infected file into the quarantine directory.

    If a file with the same name already exists in quarantine, a timestamp
    suffix is appended to prevent overwriting.

    Parameters
    ----------
    file_path     : str  Path of the infected file.
    quarantine_dir: str  Destination quarantine folder.

    Returns
    -------
    bool  True if quarantine succeeded, False otherwise.
    """
    # Ensure the quarantine directory exists
    os.makedirs(quarantine_dir, exist_ok=True)

    filename    = os.path.basename(file_path)
    destination = os.path.join(quarantine_dir, filename)

    # Avoid name collisions by appending a timestamp
    if os.path.exists(destination):
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        name, ext   = os.path.splitext(filename)
        destination = os.path.join(quarantine_dir, f"{name}_{timestamp}{ext}")

    try:
        shutil.move(file_path, destination)
        log(f"Quarantined  : '{file_path}' → '{destination}'", "INFO")
        return True
    except PermissionError:
        log(f"Cannot quarantine (permission denied): '{file_path}'", "ERROR")
    except OSError as exc:
        log(f"Failed to quarantine '{file_path}': {exc}", "ERROR")

    return False


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 4: Recursively collect all file paths inside a folder
# ─────────────────────────────────────────────────────────────────────────────

def gather_files(scan_dir: str) -> list:
    """
    Walk a directory tree and collect the absolute path of every file.

    Skips the quarantine directory to avoid re-scanning already-flagged files.

    Parameters
    ----------
    scan_dir : str  Root directory to begin the walk.

    Returns
    -------
    list  Sorted list of absolute file paths.
    """
    file_paths = []
    quarantine_abs = os.path.abspath(QUARANTINE_DIR)

    for root, dirs, files in os.walk(scan_dir):
        # Prevent descending into the quarantine folder itself
        dirs[:] = [
            d for d in dirs
            if os.path.abspath(os.path.join(root, d)) != quarantine_abs
        ]
        for filename in files:
            full_path = os.path.abspath(os.path.join(root, filename))
            file_paths.append(full_path)

    return sorted(file_paths)


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 5: Core scanning engine
# ─────────────────────────────────────────────────────────────────────────────

def scan_directory(scan_dir: str, signatures: set) -> dict:
    """
    Scan every file in scan_dir, compare hashes to signatures, and quarantine
    any matches.

    Parameters
    ----------
    scan_dir   : str  Directory to scan.
    signatures : set  Set of known malware SHA-256 hashes.

    Returns
    -------
    dict  Summary dictionary with keys:
              total_scanned, infected, clean, skipped, infected_files
    """
    results = {
        "total_scanned" : 0,
        "infected"      : 0,
        "clean"         : 0,
        "skipped"       : 0,          # Files we could not hash
        "infected_files": []          # List of (path, hash) tuples
    }

    files = gather_files(scan_dir)

    if not files:
        log("No files found in the target directory.", "WARN")
        return results

    total = len(files)
    log(f"Starting scan of {total} file(s) in '{scan_dir}' ...")
    log("-" * 70)

    for index, file_path in enumerate(files, start=1):
        # Progress indicator
        log(f"[{index:>4}/{total}] Scanning: {file_path}")

        file_hash = compute_sha256(file_path)

        if file_hash is None:
            # Hashing failed; count as skipped
            results["skipped"] += 1
            continue

        results["total_scanned"] += 1

        if file_hash in signatures:
            # ── THREAT DETECTED ──────────────────────────────────────────────
            log(f"*** THREAT DETECTED ***  Hash: {file_hash}", "THREAT")
            log(f"    File: '{file_path}'", "THREAT")

            results["infected"] += 1
            results["infected_files"].append((file_path, file_hash))

            quarantine_file(file_path, QUARANTINE_DIR)
        else:
            # ── CLEAN FILE ────────────────────────────────────────────────────
            results["clean"] += 1

    return results


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 6: Print and log the final summary
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(results: dict, scan_dir: str, start_time: datetime) -> None:
    """
    Display a formatted scan summary on the console and write it to the log.

    Parameters
    ----------
    results    : dict      The dictionary returned by scan_directory().
    scan_dir   : str       The folder that was scanned.
    start_time : datetime  When the scan began (for elapsed-time calculation).
    """
    elapsed  = (datetime.now() - start_time).total_seconds()
    divider  = "=" * 70

    summary_lines = [
        "",
        divider,
        "  SCAN COMPLETE – SUMMARY REPORT",
        divider,
        f"  Target Directory : {scan_dir}",
        f"  Scan Duration    : {elapsed:.2f} seconds",
        f"  Total Files Found: {results['total_scanned'] + results['skipped']}",
        f"  Files Scanned    : {results['total_scanned']}",
        f"  Files Skipped    : {results['skipped']}  (read errors / no permission)",
        f"  Clean Files      : {results['clean']}",
        f"  Infected Files   : {results['infected']}",
        divider,
    ]

    if results["infected"] > 0:
        summary_lines.append("  INFECTED FILES QUARANTINED:")
        for path, file_hash in results["infected_files"]:
            summary_lines.append(f"    • {path}")
            summary_lines.append(f"      SHA-256: {file_hash}")
    else:
        summary_lines.append("  ✔  No threats detected. All scanned files appear clean.")

    summary_lines.append(divider)
    summary_lines.append(f"  Log saved to : {os.path.abspath(LOG_FILE)}")
    summary_lines.append(divider)
    summary_lines.append("")

    for line in summary_lines:
        print(line)
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as log_file:
                log_file.write(line + "\n")
        except OSError:
            pass  # Logging failure should never crash the scanner


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Program entry point.

    1. Print banner.
    2. Prompt the user for a directory to scan.
    3. Load signatures from file.
    4. Run the scan.
    5. Print and log the summary.
    """
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║       Basic Antivirus Simulation — SHA-256 Signature Scanner        ║
║                  [ EDUCATIONAL PURPOSE ONLY ]                       ║
║  This tool does NOT detect real malware without real signatures.    ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

    # ── 1. Get target directory from user ────────────────────────────────────
    while True:
        scan_dir = input("Enter the full path of the folder to scan: ").strip()
        if not scan_dir:
            print("[!] Path cannot be empty. Please try again.")
            continue
        if not os.path.isdir(scan_dir):
            print(f"[!] '{scan_dir}' is not a valid directory. Please try again.")
            continue
        break

    # ── 2. Initialise the log file with a header ─────────────────────────────
    start_time = datetime.now()
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(f"\n{'='*70}\n")
        log_file.write(f"  NEW SCAN STARTED: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write(f"  Target: {scan_dir}\n")
        log_file.write(f"{'='*70}\n")

    # ── 3. Load malware signatures ────────────────────────────────────────────
    signatures = load_signatures(SIGNATURES_FILE)

    # ── 4. Run the scan ───────────────────────────────────────────────────────
    results = scan_directory(scan_dir, signatures)

    # ── 5. Display the summary ────────────────────────────────────────────────
    print_summary(results, scan_dir, start_time)


if __name__ == "__main__":
    main()
