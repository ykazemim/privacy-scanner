import argparse
import errno
import json
import os
import sys
from dataclasses import asdict, dataclass
from itertools import combinations
from pathlib import Path
from string import ascii_letters, digits

CANDIDATE_CHARACTERS = frozenset(ascii_letters + digits + ".-_@")
STDIO_MARKER = "-"


@dataclass(frozen=True)
class Finding:
    type: str
    line: int
    column: int
    length: int


def _is_ascii_alphanumeric(character: str) -> bool:
    return character.isascii() and character.isalnum()


def _is_email(candidate: str) -> bool:
    if candidate.count("@") != 1:
        return False

    local, domain = candidate.split("@")
    for part in local.split("."):
        if not part or not (
                _is_ascii_alphanumeric(part[0]) and _is_ascii_alphanumeric(part[-1])
        ):
            return False
        if any(not (_is_ascii_alphanumeric(c) or c in "-_") for c in part):
            return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or not (
                _is_ascii_alphanumeric(label[0]) and _is_ascii_alphanumeric(label[-1])
        ):
            return False
        if any(not (_is_ascii_alphanumeric(c) or c == "-") for c in label):
            return False

    tld = labels[-1]
    return len(tld) >= 2 and tld.isascii() and tld.isalpha()


def _is_phone(candidate: str) -> bool:
    return (
            len(candidate) == 11
            and candidate.startswith("09")
            and candidate.isascii()
            and candidate.isdigit()
    )


def _is_ipv4(candidate: str) -> bool:
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not (1 <= len(part) <= 3 and part.isascii() and part.isdigit()):
            return False
        if len(part) > 1 and part.startswith("0"):
            return False
        if int(part) > 255:
            return False
    return True


def _classify(candidate: str) -> str | None:
    if _is_email(candidate):
        return "EMAIL"
    if _is_phone(candidate):
        return "PHONE"
    if _is_ipv4(candidate):
        return "IP"
    return None


def scan(text: str, start_line: int = 1) -> tuple[str, list[Finding]]:
    output: list[str] = []
    findings: list[Finding] = []
    index = 0
    line = start_line
    column = 1

    while index < len(text):
        character = text[index]
        if character not in CANDIDATE_CHARACTERS:
            output.append(character)
            if character == "\n":
                line += 1
                column = 1
            else:
                column += 1
            index += 1
            continue

        start = index
        while index < len(text) and text[index] in CANDIDATE_CHARACTERS:
            index += 1

        candidate = text[start:index]
        value = candidate.rstrip(".")
        kind = _classify(value)
        if kind is None:
            output.append(candidate)
        else:
            output.append(f"[{kind}]")
            output.append(candidate[len(value):])
            findings.append(Finding(kind, line, column, len(value)))
        column += len(candidate)

    return "".join(output), findings


def scan_stream(source, destination, collect: bool = False) -> tuple[int, list[Finding]]:
    total = 0
    findings: list[Finding] = []

    for line_number, line in enumerate(source, start=1):
        sanitized, line_findings = scan(line, start_line=line_number)
        destination.write(sanitized)
        total += len(line_findings)
        if collect:
            findings.extend(line_findings)

    return total, findings


def _write_report(report_path: Path, findings: list[Finding]) -> None:
    with report_path.open("w", encoding="utf-8", newline="") as destination:
        json.dump(
            {
                "total_detected": len(findings),
                "findings": [asdict(finding) for finding in findings],
            },
            destination,
            indent=2,
        )
        destination.write("\n")


def _configure_stdio() -> None:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="surrogateescape", newline="\n")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(
            encoding="utf-8",
            errors="surrogateescape",
            newline="\n",
            line_buffering=True,
        )


def _is_closed_pipe(error: OSError) -> bool:
    return isinstance(error, BrokenPipeError) or (
            os.name == "nt" and error.errno == errno.EINVAL
    )


def _silence_stdout() -> None:
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass


def _run_stdio(prog: str, report_path: Path | None) -> None:
    _configure_stdio()
    if sys.stdin.isatty():
        finish = "Ctrl+Z then Enter" if os.name == "nt" else "Ctrl+D"
        print(f"{prog}: reading from stdin, press {finish} to finish", file=sys.stderr)

    try:
        total, findings = scan_stream(
            sys.stdin, sys.stdout, collect=report_path is not None
        )
        sys.stdout.flush()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except OSError as error:
        if not _is_closed_pipe(error):
            raise
        _silence_stdout()
        raise SystemExit(0)

    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        _write_report(report_path, findings)
    print(f"{prog}: {total} item(s) replaced", file=sys.stderr)


def _run_file(parser: argparse.ArgumentParser, input_path: Path, output_dir: Path) -> None:
    sanitized_path = output_dir / "sanitized.txt"
    report_path = output_dir / "report.json"

    for left, right in combinations((input_path, sanitized_path, report_path), 2):
        if left.resolve() == right.resolve() or (
                left.exists() and right.exists() and left.samefile(right)
        ):
            parser.error("input and output files must be distinct")

    with input_path.open(encoding="utf-8", newline="") as source:
        sanitized, findings = scan(source.read())

    output_dir.mkdir(parents=True, exist_ok=True)
    with sanitized_path.open("w", encoding="utf-8", newline="") as destination:
        destination.write(sanitized)
    _write_report(report_path, findings)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replace emails, Iranian mobile numbers, and IPv4 addresses."
    )
    parser.add_argument(
        "input",
        type=Path,
        help=(
            "UTF-8 input file, or '-' to stream stdin to stdout "
            "(sanitized text on stdout, summary on stderr)"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="output directory for sanitized.txt and report.json (default: .); "
             "not used with '-'",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="with '-': also write the JSON report to this file",
    )
    args = parser.parse_args()
    use_stdio = str(args.input) == STDIO_MARKER

    if use_stdio and args.output_dir is not None:
        parser.error("--output-dir cannot be used with '-'; use --report instead")
    if not use_stdio and args.report is not None:
        parser.error("--report is only used with '-'")

    try:
        if use_stdio:
            _run_stdio(parser.prog, args.report)
        else:
            _run_file(parser, args.input, args.output_dir or Path("."))
    except (OSError, UnicodeError) as error:
        parser.exit(1, f"{parser.prog}: error: {error}\n")


if __name__ == "__main__":
    main()
