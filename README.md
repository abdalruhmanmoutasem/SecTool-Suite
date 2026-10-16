# SecTool Suite

A small Python cybersecurity learning project containing defensive log analysis, basic TCP port checks, authorized website path checks, SHA-256 hashing, file integrity verification, and JSON reports.

## Features

- **Log Analyzer:** extracts valid and invalid IPv4 addresses and reports line numbers.
- **Brute-force detection:** flags an IP with at least N failed-login events inside a rolling time window.
- **TCP Port Scanner:** scans user-selected ports on an IPv4 target.
- **Directory Scanner:** checks common paths on an explicitly authorized website.
- **SHA-256 tools:** hashes text/files and verifies file integrity.
- **JSON reports:** save log, brute-force, port, and directory scan results.
- **Automated tests:** run with `unittest`.

## Setup (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, you can skip activation and run:
`\.venv\Scripts\python.exe -m pip install -r requirements.txt`

## Run interactive menu

```powershell
python sectool.py
```

## CLI examples

```powershell
python sectool.py log samples/sample.log
python sectool.py log samples/sample.log --json reports/log-report.json
python sectool.py bruteforce samples/bruteforce.log --threshold 3 --window 5 --json reports/bruteforce-report.json
python sectool.py hash "hello world"
python sectool.py hash samples/sample.log --file
python sectool.py verify samples/sample.log YOUR_EXPECTED_SHA256
python sectool.py ports 127.0.0.1 --ports 22,80,443
python sectool.py dirs https://example.com
```

Use network-scanning features only against systems you own or have explicit permission to test. A closed-or-filtered port result does not prove that a service is absent; a firewall may be blocking probes.

## Tests

```powershell
python -m unittest discover -v
```

The tests mock network calls and do not scan external systems.

## Scope and limitations

This is an educational starter toolkit, not a production-grade SIEM or vulnerability scanner. Brute-force detection depends on the log format shown in `samples/bruteforce.log`. Events without a parseable timestamp, a valid IPv4 address, and the phrase `Failed login` are ignored.
