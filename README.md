# Privacy Scanner
[![CI](https://github.com/MohsenDowlati/privacy-scanner/actions/workflows/ci.yaml/badge.svg)](https://github.com/MohsenDowlati/privacy-scanner/actions/workflows/ci.yaml)


A character-based scanner that redacts email addresses, Iranian mobile numbers,
and IPv4 addresses from text files. Uses Python 3.10+ and the standard library.
No installation is needed.

## 🌐 Run

```sh
python3 privacy_scanner.py examples/input.txt --output-dir output
```

The output directory is created if needed. Each run writes `sanitized.txt` and
`report.json`, replacing existing outputs. Without `--output-dir`, both files go
in the current directory. The input must be UTF-8 and can have any extension.
Input and output paths must refer to distinct files.

The JSON report lists detections in source order with their type, original line,
column, and length. Lines and columns start at 1. Tabs count as one character;
lengths and columns count Unicode characters, not bytes.

### Streaming from stdin

Pass `-` as the input to read from stdin and write the sanitized text to stdout.
This works in pipes and with live log streams:

```sh
cat app.log | python3 privacy_scanner.py - > clean.log
tail -f app.log | python3 privacy_scanner.py - | grep ERROR
python3 privacy_scanner.py - --report report.json < app.log > clean.log
```

On Windows (use `py` if `python3` is unavailable):

```bat
type app.log | py privacy_scanner.py - > clean.log
```

```powershell
Get-Content app.log -Wait -Tail 0 | py privacy_scanner.py -
```

- Input is processed line by line and written immediately, so output appears
  while the stream is still open. Findings are not kept in memory unless
  `--report` is used.
- Only sanitized text goes to stdout. A summary (`N item(s) replaced`) goes to
  stderr, so pipes stay clean.
- No files are written by default. `--report PATH` writes the same JSON report
  as file mode. `--output-dir` cannot be combined with `-`, and `--report` is
  only valid with `-`.
- Behavior is identical on Linux, macOS, and Windows: stdin and stdout are
  forced to UTF-8, line endings are never translated, and bytes that are not
  valid UTF-8 pass through unchanged instead of stopping the stream.
- Closing the reader early (for example `| head`) ends the scan quietly with
  exit code 0. Ctrl+C exits with code 130.

## 🗣️ Scanning rules

The scanner reads maximal candidates containing `A-Z`, `a-z`, `0-9`, `.`, `-`,
`_`, or `@`. It sets aside trailing periods, then validates the entire remaining
candidate. Invalid candidates stay unchanged; valid substrings inside them are
never extracted. Trailing periods and all separators are preserved.

- **Email:** dot-separated local parts with ASCII letters, digits, `-`, and `_`;
  each part starts and ends with a letter or digit. The domain has at least two
  labels, permits internal hyphens, and ends with at least two ASCII letters.
- **Phone:** exactly 11 ASCII digits starting with `09`.
- **IPv4:** four decimal octets from 0 to 255, with no leading zeros.

LF and CRLF line endings are preserved. A standalone CR counts as an ordinary
character.

Scanning takes O(n) time. File mode holds the input, sanitized text, and findings in memory; stdin mode `-` uses memory proportional to the longest line, plus findings only when `--report` is set.

## 🔧 Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests cover validation, candidate boundaries, punctuation, Unicode, source
positions, line endings, file execution, and stdin/stdout streaming (including live output, byte preservation, and early pipe closure).

## 🔨 My Contributions
- Added a CI workflow that runs tests across Ubuntu, macOS, and Windows with Python 3.10–3.13.
- Added project packaging metadata and the privacy-scanner console-script entry point, with checks for editable installation and `pipx` installation.
- Added CI checks for linting, security analysis, and package builds.
- Improved test portability on Windows by skipping symlink tests when symlink creation is unavailable, and made the subprocess.run test behavior explicit for Ruff.
text
- Added `-` support for streaming stdin to stdout, with UTF-8, newline, and broken-pipe handling that behaves the same on Ubuntu, macOS, and Windows, plus tests for it.
