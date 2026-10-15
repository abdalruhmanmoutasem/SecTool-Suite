# SecTool Suite

A Python-based command-line security toolkit that combines basic security utilities in one interactive menu.

## Features

### 1. Port Scanner
- Scans a predefined list of TCP ports on a target IP address.
- Identifies ports that accept TCP connections.
- Uses connection timeouts to avoid waiting too long on unresponsive ports.

Ports scanned: `21`, `22`, `80`, `443`, `3306`, `8080`.

### 2. Web Directory Scanner
- Checks a predefined list of common web paths.
- Reports HTTP `200` responses and `403` responses.
- Uses request timeouts and handles connection failures.

Paths checked: `admin`, `login`, `dashboard`, `images`, `config`, `test`.

### 3. Log IP Extractor
- Extracts IPv4-like patterns from sample log data.
- Uses regular expressions to identify IP address patterns.
- Prints the extracted results.

The current version analyzes sample data embedded in the Python script.

### 4. SHA-256 Hash Generator
- Accepts text from the user.
- Generates a SHA-256 hash using Python's `hashlib` module.
- Prints the resulting hexadecimal digest.

## Requirements

- Python 3.10 or later
- `requests` library

## Installation

Clone the repository:

```bash
git clone <YOUR-REPOSITORY-URL>
cd <YOUR-REPOSITORY-DIRECTORY>
```

Install the required dependency:

```bash
python -m pip install requests
```

## Usage

Run the program:

```bash
python main.py
```

Replace `main.py` with the actual Python filename if it is different.

Choose an option from the interactive menu:

1. Port Scanner
2. Web Directory Scanner
3. Log IP Extractor
4. Hash Generator
5. Exit

## Example

Example output from the port scanner:

```text
--- [1] Port Scanner ---
Enter target IP (e.g., 127.0.0.1): 127.0.0.1
[*] Scanning 127.0.0.1...
[+] Port 80 is OPEN
```

The output depends on the target system and the services listening on its ports.

## Technologies Used

- Python
- `socket` for TCP connection checks
- `requests` for HTTP requests
- `re` for pattern matching
- `hashlib` for SHA-256 hashing
- `datetime` imported for potential future use

## Limitations

- The port list is predefined and cannot currently be customized through the menu.
- The directory wordlist is predefined.
- The log extractor uses hardcoded sample data rather than reading log files.
- The IP extraction pattern does not validate whether each extracted address is a valid IPv4 address.
- The hash generator hashes text, not files.
- Automated tests and report exports are not included in this version.

## Responsible Use

Use this tool only on systems and websites you own or have explicit permission to test.

Avoid scanning third-party systems without authorization.

## Project Status

This project is an educational prototype. Future improvements may include input validation, better error handling, log file analysis, automated tests, and JSON report generation.

## License

No license has been added yet. Add a license file before permitting others to reuse or distribute this project.
