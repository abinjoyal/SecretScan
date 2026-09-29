"""
CLI entry point for SecretScan command-line utility.
"""

import argparse
import os
import sys
from secretscan.patterns import PatternLoader
from secretscan.detector import SecretDetector
from secretscan.scanner import DirectoryScanner
from secretscan.reporter import ConsoleReporter, ReportExporter
from secretscan import __version__


def install_git_pre_commit_hook(target_dir: str = ".") -> None:
    """
    Installs a git pre-commit hook in .git/hooks/pre-commit to automatically scan before committing.
    """
    git_dir = os.path.join(os.path.abspath(target_dir), ".git")
    if not os.path.isdir(git_dir):
        print(f"Error: '{target_dir}' is not a valid git repository (no .git folder found).")
        sys.exit(1)

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, "pre-commit")

    hook_script = """#!/bin/sh
# SecretScan pre-commit hook
echo "🔒 Running SecretScan pre-commit security check..."
python -m secretscan.main .
if [ $? -ne 0 ]; then
    echo "❌ SecretScan detected potential secrets! Commit aborted."
    exit 1
fi
echo "✔ SecretScan security check passed."
"""

    with open(hook_path, "w", encoding="utf-8") as f:
        f.write(hook_script)

    try:
        os.chmod(hook_path, 0o755)
    except Exception:
        pass

    print(f"✔ SecretScan pre-commit hook successfully installed at: {hook_path}")
    sys.exit(0)


def run_interactive_mode(result) -> None:
    """
    Interactively prompts developer for each finding in terminal.
    """
    if not result.matches:
        return

    print("\n--- SecretScan Interactive Review Mode ---")
    kept_matches = []
    for idx, match in enumerate(result.matches, start=1):
        print(f"\nFinding [{idx}/{len(result.matches)}]:")
        print(f"  File:  {match.file_path}")
        print(f"  Line:  {match.line_number}")
        print(f"  Type:  {match.secret_type}")
        print(f"  Value: {match.masked_value}")
        print(f"  Snippet: {match.line_snippet}")

        choice = input("Action -> [k]eep issue, [i]gnore, [q]uit: ").strip().lower()
        if choice == "q":
            print("Quitting interactive review.")
            break
        elif choice == "i":
            print(f"Ignored finding in {match.file_path}:{match.line_number}")
        else:
            kept_matches.append(match)

    result.matches = kept_matches


def main():
    parser = argparse.ArgumentParser(
        prog="secretscan",
        description="SecretScan - Local security utility to scan codebases for exposed secrets."
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the directory or file to scan (default: current directory)."
    )

    parser.add_argument(
        "-o", "--output",
        help="Path to output file for saving scan report."
    )

    parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Report export format (default: text)."
    )

    parser.add_argument(
        "-c", "--config",
        help="Path to custom rules.json configuration file."
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output including file progress and snippets."
    )

    parser.add_argument(
        "-e", "--exclude",
        nargs="+",
        help="Additional directories to ignore during scan (e.g. --exclude tests docs)."
    )

    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive review mode to keep or ignore findings."
    )

    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install git pre-commit hook in .git/hooks/pre-commit."
    )

    parser.add_argument(
        "--max-size",
        type=int,
        default=5,
        help="Maximum file size limit in Megabytes (default: 5MB)."
    )

    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Disable Shannon Entropy calculation engine."
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"SecretScan {__version__}"
    )

    args = parser.parse_args()

    # Handle git hook installation request
    if args.install_hook:
        install_git_pre_commit_hook(args.path)

    # Load rules and initialize detector and scanner
    rules = PatternLoader.load_rules(args.config)
    detector = SecretDetector(rules=rules, enable_entropy=not args.no_entropy)

    from secretscan.utils import DEFAULT_IGNORED_DIRS
    ignored_dirs = set(DEFAULT_IGNORED_DIRS)
    if args.exclude:
        for exc in args.exclude:
            for item in exc.split(","):
                item_clean = item.strip()
                if item_clean:
                    ignored_dirs.add(item_clean)

    max_size_bytes = args.max_size * 1024 * 1024
    scanner = DirectoryScanner(
        detector=detector,
        ignored_dirs=ignored_dirs,
        max_file_size_bytes=max_size_bytes
    )

    # Progress tracking callback
    def show_progress(filename: str, count: int):
        if args.verbose:
            print(f"[{count}] Scanning: {filename}")

    # Run scan
    result = scanner.scan_directory(args.path, progress_callback=show_progress)

    # Interactive mode if requested
    if args.interactive:
        run_interactive_mode(result)

    # Output results to console
    ConsoleReporter.print_results(result, verbose=args.verbose)

    # Save report if output option provided
    if args.output:
        if args.format == "json":
            ReportExporter.export_json(result, args.output)
            print(f"Report saved as JSON to: {args.output}")
        elif args.format == "html":
            ReportExporter.export_html(result, args.output)
            print(f"Report saved as HTML to: {args.output}")
        else:
            ReportExporter.export_text(result, args.output)
            print(f"Report saved as Text to: {args.output}")

    # Exit code: 0 if clean, 1 if findings present
    if result.matches:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
