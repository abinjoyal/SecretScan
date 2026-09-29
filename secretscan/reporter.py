"""
Report generator for outputting scan results to terminal, text, JSON, or HTML files.
"""

import json
import os
from typing import Optional
from secretscan.scanner import ScanResult

try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    Fore = None
    Style = None


class ConsoleReporter:
    """Formats and prints scan results to standard output."""

    @staticmethod
    def print_results(result: ScanResult, verbose: bool = False) -> None:
        title = "SecretScan"
        divider = "─────────────────────────────────────────"

        print(f"\n{title}")
        print(divider)
        print(f"\nScanning: {result.target_path}\n")
        print(f"Files scanned: {result.files_scanned}")
        print(f"Potential secrets found: {len(result.matches)}\n")

        if not result.matches:
            if HAS_COLORAMA:
                print(f"{Fore.GREEN}✔ No potential secrets detected!{Style.RESET_ALL}\n")
            else:
                print("✔ No potential secrets detected!\n")
            print(divider)
            print(f"Scan completed.\n")
            return

        for match in result.matches:
            if HAS_COLORAMA:
                warning_label = f"{Fore.YELLOW}⚠ Potential Secret{Style.RESET_ALL}"
                type_str = f"{Fore.CYAN}{match.secret_type}{Style.RESET_ALL}"
                val_str = f"{Fore.RED}{match.masked_value}{Style.RESET_ALL}"
            else:
                warning_label = "⚠ Potential Secret"
                type_str = match.secret_type
                val_str = match.masked_value

            print(f"{warning_label}\n")
            print(f"File: {match.file_path}")
            print(f"Line: {match.line_number}")
            print(f"Type: {type_str}")
            print(f"Value: {val_str}\n")
            if verbose:
                print(f"Snippet: {match.line_snippet}\n")

        print(divider)
        print("Scan completed.\n")
        print(f"Files scanned: {result.files_scanned}")
        print(f"Issues found: {len(result.matches)}\n")


class ReportExporter:
    """Saves scan results to structured JSON, plain text, or interactive HTML files."""

    @staticmethod
    def export_json(result: ScanResult, output_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        report_data = {
            "target_path": result.target_path,
            "files_scanned": result.files_scanned,
            "lines_scanned": result.lines_scanned,
            "duration_seconds": result.duration_seconds,
            "issues_count": len(result.matches),
            "findings": [
                {
                    "file": m.file_path,
                    "line": m.line_number,
                    "type": m.secret_type,
                    "masked_value": m.masked_value
                }
                for m in result.matches
            ],
            "errors": result.errors
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    @staticmethod
    def export_text(result: ScanResult, output_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("SecretScan Security Report\n")
            f.write("=" * 40 + "\n")
            f.write(f"Target Path: {result.target_path}\n")
            f.write(f"Files Scanned: {result.files_scanned}\n")
            f.write(f"Lines Scanned: {result.lines_scanned}\n")
            f.write(f"Duration: {result.duration_seconds} seconds\n")
            f.write(f"Issues Found: {len(result.matches)}\n")
            f.write("=" * 40 + "\n\n")

            for m in result.matches:
                f.write(f"[WARNING] Potential Secret\n")
                f.write(f"  File:  {m.file_path}\n")
                f.write(f"  Line:  {m.line_number}\n")
                f.write(f"  Type:  {m.secret_type}\n")
                f.write(f"  Value: {m.masked_value}\n\n")

    @staticmethod
    def export_html(result: ScanResult, output_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        rows = ""
        for idx, m in enumerate(result.matches, start=1):
            rows += f"""
            <tr>
                <td>{idx}</td>
                <td><code>{m.file_path}</code></td>
                <td><span class="badge badge-line">Line {m.line_number}</span></td>
                <td><span class="badge badge-type">{m.secret_type}</span></td>
                <td><code class="masked">{m.masked_value}</code></td>
            </tr>
            """

        status_class = "status-clean" if len(result.matches) == 0 else "status-warning"
        status_text = "PASSED - No Secrets Found" if len(result.matches) == 0 else f"ACTION REQUIRED - {len(result.matches)} Issues Detected"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecretScan Security Report</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --accent-green: #238636;
            --accent-red: #da3633;
            --accent-yellow: #d29922;
            --accent-blue: #58a6ff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
            color: #ffffff;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            color: #ffffff;
            margin-top: 5px;
        }}
        .stat-label {{
            font-size: 14px;
            color: var(--text-muted);
        }}
        .status-badge {{
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
        }}
        .status-clean {{ background: rgba(35, 134, 54, 0.2); color: #3fb950; border: 1px solid #238636; }}
        .status-warning {{ background: rgba(218, 54, 51, 0.2); color: #f85149; border: 1px solid #da3633; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 14px 18px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background: #21262d;
            color: var(--text-muted);
            font-size: 13px;
            text-transform: uppercase;
        }}
        code {{
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            background: rgba(110, 118, 129, 0.2);
            padding: 3px 6px;
            border-radius: 4px;
            color: var(--accent-blue);
        }}
        code.masked {{
            color: #ff7b72;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }}
        .badge-type {{ background: rgba(88, 166, 255, 0.15); color: var(--accent-blue); }}
        .badge-line {{ background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>SecretScan Security Report</h1>
                <p style="color: var(--text-muted); margin: 5px 0 0 0;">Target: <code>{result.target_path}</code></p>
            </div>
            <div>
                <span class="status-badge {status_class}">{status_text}</span>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Files Scanned</div>
                <div class="stat-value">{result.files_scanned}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Lines Scanned</div>
                <div class="stat-value">{result.lines_scanned}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Potential Secrets</div>
                <div class="stat-value" style="color: {'#3fb950' if len(result.matches)==0 else '#f85149'}">{len(result.matches)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Duration</div>
                <div class="stat-value">{result.duration_seconds}s</div>
            </div>
        </div>

        {"<p style='text-align: center; padding: 40px; background: var(--card-bg); border-radius: 8px; border: 1px solid var(--border-color); color: #3fb950;'>✔ No potential secrets detected in this project!</p>" if not result.matches else f'''
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>File Path</th>
                    <th>Line</th>
                    <th>Secret Type</th>
                    <th>Masked Value</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        '''}
    </div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
