# GeminiHunter

Google Gemini and Google API key discovery and security assessment tool.

GeminiHunter crawls web assets and Android application packages for exposed
Google API keys (the `AIza...` family), recovers keys that have been hidden
through common obfuscation techniques, validates discovered keys against live
Google endpoints, and profiles what an exposed key is actually able to do so
that impact can be assessed and reported.

---

## Authorized Use Only

This tool is intended exclusively for authorized security testing, such as
penetration testing engagements, bug bounty programs that permit it, and
assessment of assets you own or have explicit written permission to test.

Scanning systems, domains, or applications without authorization may be
illegal. Any keys recovered are real credentials belonging to their owners.
Do not use, store, or disclose them outside the terms of your engagement.
Follow responsible disclosure practices. You are solely responsible for how
you use this tool.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Mode](#interactive-mode)
  - [Command-Line Mode](#command-line-mode)
  - [Command-Line Options](#command-line-options)
- [Recommended Workflow: Bulk Domain Input via Chaos](#recommended-workflow-bulk-domain-input-via-chaos)
- [Android Application Scanning](#android-application-scanning)
- [Key Validation](#key-validation)
- [Capability and Impact Analysis](#capability-and-impact-analysis)
- [Detection Capabilities](#detection-capabilities)
- [Output Files](#output-files)
- [Legal Disclaimer](#legal-disclaimer)
- [License](#license)

---

## Features

- Web asset scanning of a single target or a bulk list of targets, including
  linked JavaScript and source map references.
- Android application scanning for `.apk`, `.xapk`, and `.apks` packages, using
  jadx when available and a hardened archive and binary-string fallback when it
  is not.
- Recovery of obfuscated keys that a plain pattern match would miss, including
  split or concatenated strings, character arrays, reversed strings, hex and
  unicode escapes, and Base64-encoded values.
- Validation of discovered keys against live Google endpoints, including a
  Referer-based restriction bypass check.
- Capability and impact profiling for confirmed keys, with evidence artifacts
  saved to disk.
- Clear, structured terminal output and plain-text result and report files.

---

## How It Works

GeminiHunter is organized as a pipeline. Each stage can be run on its own or
chained with the others:

1. Discovery. Crawl web targets or decompose an Android package to collect
   source content.
2. Extraction. Run every piece of source content through the pattern matcher
   and the de-obfuscation engine to recover candidate keys.
3. Validation. Probe each candidate key against live Google endpoints to
   determine whether it is active and whether access restrictions can be
   bypassed.
4. Impact analysis. For confirmed keys, map which capabilities the key can
   reach and record supporting evidence.

---

## Requirements

- Python 3.8 or newer.
- Python packages: `requests`, `colorama`, `urllib3`, `tqdm`.
- Optional: `jadx` on the system PATH for deep Android decompilation. Without
  it, Android scanning falls back to an archive and binary-string scan.
- Optional: `ffmpeg` on the system PATH for converting audio evidence produced
  during capability analysis. Without it, raw audio output is retained instead.

No additional tooling is required to supply targets. A domain list can be
prepared manually or downloaded from a public dataset such as Chaos, then
passed directly to GeminiHunter.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/defaultsecc/GeminiHunter.git
cd GeminiHunter
```

Create and activate a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the Python dependencies:

```bash
pip install requests colorama urllib3 tqdm
```

Alternatively, create a `requirements.txt` with the following contents and
install from it:

```
requests
colorama
urllib3
tqdm
```

```bash
pip install -r requirements.txt
```

Optional components:

```bash
# Debian / Ubuntu / Kali
sudo apt update
sudo apt install jadx ffmpeg
```

---

## Usage

GeminiHunter can be run interactively through a menu, or non-interactively with
command-line flags for automation and scripting.

### Interactive Mode

Run the script with no arguments to open the operation menu:

```bash
python3 geminihunter.py
```

Available modules:

1. Recon Sweep. Crawl a single domain or URL for exposed secrets.
2. Mass Recon. Load a target list and scan them in bulk.
3. Source Inspector. Scan a list of JavaScript source URLs for embedded secrets.
4. Android Inspector. Scan an APK, XAPK, or APKS package for embedded secrets.
5. Credential Probe. Validate discovered keys against live APIs, in direct or
   Referer-bypass mode.
6. Impact Profiler. Map the capabilities and potential impact of a confirmed key.
7. Terminate. Exit.

### Command-Line Mode

Scan a single target:

```bash
python3 geminihunter.py -t example.com
```

Scan a list of targets from a file:

```bash
python3 geminihunter.py -f targets.txt -o results.txt
```

Scan an Android application package:

```bash
python3 geminihunter.py -a application.apk
```

Validate a file of discovered keys:

```bash
python3 geminihunter.py -l results.txt --verify -o vulnerable.txt
```

### Command-Line Options

| Option | Argument | Description |
| --- | --- | --- |
| `-t`, `--target` | domain or URL | Scan a single target. |
| `-f`, `--file` | file path | Scan a list of targets, one per line. |
| `-a`, `--apk` | file path | Scan an APK, XAPK, or APKS package. |
| `-l`, `--list` | file path | File of API keys to validate. |
| `--verify` | | Enable key validation mode. |
| `-o`, `--output` | file path | Output file. Defaults to `results.txt`. |
| `--timeout` | seconds | Per-request timeout. Defaults to 8. |
| `-q`, `--quiet` | | Reduce terminal output. |
| `-h`, `--help` | | Show the quick reference. |

Target files should contain one domain or URL per line. Lines beginning with
`#` are treated as comments and ignored.

---

## Recommended Workflow: Bulk Domain Input via Chaos

For wide-scope assessments, a ready-made domain list can be obtained from the
Chaos dataset and passed straight to GeminiHunter. Chaos is a public collection
of domains and subdomains maintained by ProjectDiscovery, available at:

```
https://chaos.projectdiscovery.io/
```

Step 1. Download a domain list.

Open the Chaos site, locate a program that is within your authorized scope, and
download its dataset. The download is a compressed archive containing one or
more text files of domains and subdomains.

Step 2. Extract the archive into a single target list.

```bash
unzip program.zip -d chaos_targets
cat chaos_targets/*.txt | sort -u > targets.txt
```

Step 3. Scan the target list for exposed Google and Gemini API keys.

```bash
python3 geminihunter.py -f targets.txt -o results.txt
```

Step 4. Validate the keys that were discovered.

```bash
python3 geminihunter.py -l results.txt --verify -o vulnerable.txt
```

Step 5. Profile the impact of confirmed keys using the Impact Profiler module
in interactive mode, supplying either a single key or the file of confirmed
keys.

Keep the scope tight. Only use domain lists that correspond to targets you are
authorized to assess.

---

## Android Application Scanning

The Android Inspector accepts a local `.apk`, `.xapk`, or `.apks` file. The tool
does not download applications itself; provide a package you already hold and
are authorized to assess, for example one pulled from a device you control.

```bash
python3 geminihunter.py -a application.apk
```

Scanning strategy:

- When jadx is installed, the package is decompiled so that both code and
  decoded resources are scanned, giving the broadest coverage.
- When jadx is not installed or produces no output, the tool performs a
  read-only archive walk, decoding text members and running printable-string
  extraction over compiled and binary members such as `classes.dex`, native
  libraries, and compiled resources.
- XAPK and APKS bundles are unpacked, and the packaged APKs inside them are
  scanned.

Archive handling is hardened against malformed or hostile packages. Path
traversal and symbolic link entries are rejected, and entry count, per-file
size, and total extracted size are capped.

---

## Key Validation

Validation probes each candidate key against live Google endpoints to determine
whether it is active. Two modes are available:

- Direct mode probes the key as-is.
- Bypass mode adds a Referer header derived from the origin where the key was
  found, to test whether an HTTP referrer restriction can be circumvented.

Confirmed keys are written to the chosen output file, for example
`vulnerable.txt`.

---

## Capability and Impact Analysis

For a confirmed key, the Impact Profiler determines which capabilities the key
can reach and records supporting evidence to disk for reporting. This supports
severity assessment and the preparation of a proof-of-concept for responsible
disclosure. Only run this against keys that fall within your authorized scope.

---

## Detection Capabilities

In addition to plain pattern matching, GeminiHunter recovers keys that have been
hidden using common obfuscation techniques. Each technique transforms the input
back toward plaintext and then re-validates candidates against the canonical key
format, so recovery does not introduce false positives. Supported forms include:

- Concatenated string literals and character arrays.
- Reversed strings.
- Hexadecimal escape sequences.
- Unicode escape sequences.
- Base64-encoded values, including URL-safe and unpadded variants.

When a key is recovered from an obfuscated form, the detection output records
the vector used.

---

## Output Files

- Results file. Discovered keys with their origin and source, written to the
  path given by `-o` (default `results.txt`).
- Vulnerable keys file. Confirmed keys from validation, for example
  `vulnerable.txt`.
- Evidence and reports. Artifacts produced during capability analysis, written
  to the tool's output directories.

---

## Legal Disclaimer

This software is provided for authorized security testing and educational
purposes only. The authors and contributors accept no liability for any misuse
or damage caused by this tool. By using it, you accept full responsibility for
your actions and confirm that you have permission to test the targets you
provide.

---


