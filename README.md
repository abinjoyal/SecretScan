# SecretScan

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**SecretScan** is a fast, local security command-line utility written in Python. It scans source-code repositories for exposed credentials and sensitive information such as API keys, passwords, private keys, and high-entropy secret tokens.

---

## Key Features

- **Recursive Directory Scanning:** Traverses target project directories while skipping build artifacts, virtual environments, and binary files.
- **Shannon Entropy Engine:** Evaluates mathematical string randomness to detect un-patterned secret tokens.
- **Git Pre-Commit Hook Integration:** Automatically prevents commits containing hardcoded secrets using `python -m secretscan.main --install-hook`.
- **Multi-Format Export Engine:** Exports findings to HTML, JSON, or Plain Text files.
- **Interactive Remediation:** Developer review mode allowing interactive decision-making (keep, ignore, quit) for individual findings.
- **Custom Rule Engine:** Configurable regular expressions via `config/rules.json`.
- **Ignore Rules Support:** Utilizes `.secretscanignore` to exclude specific project files and directories.
- **Credential Masking:** Automatically redacts detected credentials in terminal and report outputs (e.g., `sk_****789`).
- **100% Local Execution:** Runs entirely on-device without external network dependencies or third-party cloud connections.

---

## Project Structure

```text
SecretScan/
├── secretscan/
│   ├── __init__.py      # Package version metadata
│   ├── main.py          # CLI entry point
│   ├── scanner.py       # File system scanner & .secretscanignore parser
│   ├── patterns.py      # Rule loader & regex definitions
│   ├── detector.py      # Secret detection engine
│   ├── entropy.py       # Shannon entropy calculator
│   ├── reporter.py      # Console, JSON, Text, & HTML exporters
│   └── utils.py         # File validators & masking tools
├── config/
│   └── rules.json       # Customizable detection rules
├── reports/             # Generated security reports directory
├── tests/               # Automated unit test suite
├── .gitignore
├── .secretscanignore    # Project level ignore file
├── requirements.txt
├── README.md
└── setup.py
```

---

## Installation

### 1. Direct Repository Clone

```bash
git clone https://github.com/abinjoyal/SecretScan.git
cd SecretScan
pip install -r requirements.txt
```

### 2. Editable Package Installation

```bash
pip install -e .
```

---

## Complete CLI Command Reference

### 1. Help & Version Information

Show CLI arguments and available options:
```bash
python -m secretscan.main --help
```

Display program version:
```bash
python -m secretscan.main --version
```

---

### 2. Basic Scanning Commands

Scan current working directory:
```bash
python -m secretscan.main .
```

Scan a specific project directory:
```bash
python -m secretscan.main "D:/Python/Python Project/ProjectStarter"
```

Run with verbose progress logging:
```bash
python -m secretscan.main . --verbose
```

---

### 3. Report Export Commands

#### Generate & View HTML Security Report

Step 1: First, run the scan to generate the HTML report:
```bash
python -m secretscan.main . --output reports/scan_report.html --format html
```

Step 2: Open the generated HTML report in your default browser (Windows PowerShell):
```powershell
Start-Process reports/scan_report.html
```

*Note: Ensure Step 1 is executed before running Step 2 to generate the report file.*

#### Export JSON Report
```bash
python -m secretscan.main . --output reports/scan_result.json --format json
```

#### Export Plain Text Summary
```bash
python -m secretscan.main . --output reports/scan_summary.txt --format text
```

---

### 4. Interactive Review Mode

Prompt the developer for each detected secret to accept or ignore findings:
```bash
python -m secretscan.main . --interactive
```

---

### 5. Advanced Scanning Controls

Exclude specific directories during scan:
```bash
python -m secretscan.main . --exclude tests docs tmp
```

Set maximum file size limit (in Megabytes):
```bash
python -m secretscan.main . --max-size 2
```

Disable Shannon Entropy calculation (Regex rules only):
```bash
python -m secretscan.main . --no-entropy
```

Use custom rule configuration file:
```bash
python -m secretscan.main . --config config/rules.json
```

---

### 6. Git Pre-Commit Hook Installation

Install Git pre-commit hook in `.git/hooks/pre-commit` to prevent committing secrets:
```bash
python -m secretscan.main --install-hook
```

---

### 7. Unit Testing

Run test suite with pytest:
```bash
pytest
```

---

## Configuration (`config/rules.json`)

Custom detection rules can be defined in `config/rules.json`:

```json
{
  "rules": [
    {
      "name": "Custom Service Token",
      "pattern": "MY_SERVICE_[A-Za-z0-9]{16,}",
      "description": "Matches custom company API service tokens."
    }
  ]
}
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
