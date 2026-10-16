# SecTool Suite

A modular Python cybersecurity toolkit built for hands-on security learning and defensive analysis.

## Features

- **Log Analysis:** Extract valid and invalid IPv4 addresses and identify their line numbers.
- **Brute-Force Detection:** Detect repeated failed login attempts from the same IP within a configurable time window.
- **TCP Port Scanner:** Check selected TCP ports on an IPv4 target.
- **Directory Scanner:** Check common website paths and report HTTP status codes.
- **SHA-256 Hashing:** Calculate hashes for text and files.
- **File Integrity Verification:** Compare a file's current hash against an expected SHA-256 value.
- **JSON Reports:** Save analysis results with a UTC generation timestamp.
- **Automated Testing:** Unit tests for core functionality and error handling.

## Requirements

- Python 3.10+
- `requests`

## Installation

```powershell
git clone https://github.com/abdalruhmanmoutasem/SecTool-Suite.git
cd SecTool-Suite
python -m pip install -r requirements.txt
```

## Usage

### Interactive menu

```powershell
python sectool.py
```

### Analyze a log file

```powershell
python sectool.py log samples/sample.log
```

Save the results as JSON:

```powershell
python sectool.py log samples/sample.log --json reports/log-report.json
```

### Detect possible brute-force activity

```powershell
python sectool.py bruteforce samples/bruteforce.log --threshold 3 --window 5
```

Save the alert report:

```powershell
python sectool.py bruteforce samples/bruteforce.log --threshold 3 --window 5 --json reports/bruteforce-report.json
```

### Calculate a file's SHA-256 hash

```powershell
python sectool.py hash samples/sample.log --file
```

### Verify file integrity

```powershell
python sectool.py verify samples/sample.log YOUR_EXPECTED_SHA256
```

### Scan TCP ports

```powershell
python sectool.py ports 127.0.0.1 --ports 22,80,443
```

### Check website paths

```powershell
python sectool.py dirs https://example.com
```

Only scan systems you own or have explicit permission to test.

## Testing

Run the complete test suite:

```powershell
python -m unittest discover -v
```

The current test suite contains 13 tests covering log analysis, brute-force detection, hashing, input validation, and mocked network operations.

## Project Structure

```text
SecTool-Suite/
├── sectool.py
├── sectool/
│   ├── dir_scanner.py
│   ├── hash_tools.py
│   ├── log_analyzer.py
│   ├── port_scanner.py
│   └── reporting.py
├── samples/
│   ├── sample.log
│   └── bruteforce.log
├── tests/
├── reports/
├── requirements.txt
└── README.md
```

## Limitations

This is an educational security toolkit, not a production-grade SIEM or vulnerability scanner. Brute-force detection depends on the log format supported by the analyzer. A port reported as closed or filtered may be blocked by a firewall.

## Author

Developed as a hands-on Python and cybersecurity learning project.