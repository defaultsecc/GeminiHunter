# GeminiHunter

Google Gemini and Google API key discovery and security assessment tool.

GeminiHunter crawls web assets and Android packages for exposed Google API keys
(the `AIza...` family), recovers keys hidden through common obfuscation, validates
them against live Google endpoints, and profiles what an exposed key can do so its
impact can be assessed and reported.

## Authorized Use Only

This tool is for authorized security testing only (penetration tests, permitted
bug bounty programs, and assets you own or have written permission to test).
Scanning without authorization may be illegal. Any keys recovered are real
credentials belonging to their owners; handle them only within the terms of your
engagement and follow responsible disclosure. You are responsible for your use of
this tool.

## Features

- Web scanning of a single target or a bulk list, including linked JavaScript.
- Android scanning for `.apk`, `.xapk`, and `.apks` packages (jadx when available,
  with a hardened archive and binary-string fallback when it is not).
- Recovery of obfuscated keys: concatenated strings, character arrays, reversed
  strings, hex and unicode escapes, and Base64 values.
- Validation of keys against live Google endpoints, including a Referer-based
  restriction bypass check.
- Capability and impact profiling for confirmed keys, with evidence saved to disk.

## Requirements

- Python 3.8 or newer
- Python packages: `requests`, `colorama`, `urllib3`, `tqdm`
- Optional: `jadx` on PATH for deep Android decompilation
- Optional: `ffmpeg` on PATH for audio evidence conversion during capability analysis

## Installation

```bash
git clone https://github.com/defaultsecc/GeminiHunter.git
cd GeminiHunter

python3 -m venv .venv
source .venv/bin/activate

pip install requests colorama urllib3 tqdm
```

Optional components (Debian / Ubuntu / Kali):

```bash
sudo apt install jadx ffmpeg
```

## Usage

Run with no arguments for the interactive menu:

```bash
python3 geminihunter.py
```

Modules: 1) Recon Sweep (single target), 2) Mass Recon (target list),
3) Source Inspector (JS URL list), 4) Android Inspector (APK/XAPK/APKS),
5) Credential Probe (validation), 6) Impact Profiler (capability analysis),
7) Terminate.

Or use the command line:

```bash
python3 geminihunter.py -t example.com                      # single target
python3 geminihunter.py -f targets.txt -o results.txt       # bulk list
python3 geminihunter.py -a application.apk                  # android package
python3 geminihunter.py -l results.txt --verify -o vulnerable.txt   # validate keys
```

### Command-Line Options

| Option | Argument | Description |
| --- | --- | --- |
| `-t`, `--target` | domain or URL | Scan a single target. |
| `-f`, `--file` | file path | Scan a list of targets, one per line. |
| `-a`, `--apk` | file path | Scan an APK, XAPK, or APKS package. |
| `-l`, `--list` | file path | File of API keys to validate. |
| `--verify` | | Enable key validation mode. |
| `-o`, `--output` | file path | Output file (default `results.txt`). |
| `--timeout` | seconds | Per-request timeout (default 8). |
| `-q`, `--quiet` | | Reduce terminal output. |

Target files take one domain or URL per line; lines starting with `#` are ignored.

## Bulk Domain Input via Chaos

A ready-made domain list can be downloaded from the Chaos dataset
(https://chaos.projectdiscovery.io/) and passed straight to GeminiHunter.

```bash
# 1. Download a program's dataset from the Chaos site (within your scope),
#    then extract it into a single target list:
unzip program.zip -d chaos_targets
cat chaos_targets/*.txt | sort -u > targets.txt

# 2. Scan the targets for exposed keys:
python3 geminihunter.py -f targets.txt -o results.txt

# 3. Validate anything found:
python3 geminihunter.py -l results.txt --verify -o vulnerable.txt
```

Only use domain lists that correspond to targets you are authorized to assess.

## Android Scanning

The Android Inspector takes a local `.apk`, `.xapk`, or `.apks` file; the tool does
not download apps. With jadx installed, packages are decompiled so code and decoded
resources are scanned. Without it, a read-only archive walk decodes text members and
runs string extraction over binary members (`classes.dex`, native libraries,
compiled resources). XAPK and APKS bundles are unpacked and their inner APKs scanned.
Archive handling rejects path-traversal and symlink entries and caps entry count and
size.

## Output Files

- `results.txt` (or `-o` value): discovered keys with origin and source.
- `vulnerable.txt`: confirmed keys from validation.
- Evidence and reports from capability analysis, written to the tool's output
  directories.

## Legal Disclaimer

This software is provided for authorized security testing and educational purposes
only. The authors accept no liability for misuse or damage. By using it you confirm
you have permission to test the targets you provide and accept full responsibility
for your actions.

## License

See the `LICENSE` file in the repository. If none is present, all rights are reserved
by the repository owner until one is added.
