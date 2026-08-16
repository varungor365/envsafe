from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

ASSIGNMENT = re.compile(r"^(?P<prefix>\s*(?:export\s+)?)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*?)(?P<newline>\n?)$")
SENSITIVE = re.compile(r"(?:pass(word)?|secret|token|api[_-]?key|private[_-]?key|credential|auth|cookie|dsn)", re.I)


@dataclass
class Entry:
    line: int
    key: str
    value: str
    raw: str
    valid: bool
    issue: str = ""


def strip_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value


def parse(text: str) -> list[Entry]:
    entries: list[Entry] = []
    for line_no, raw in enumerate(text.splitlines(keepends=True), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ASSIGNMENT.match(raw)
        if not match:
            entries.append(Entry(line_no, "", "", raw, False, "malformed assignment"))
            continue
        key, value = match.group("key"), strip_value(match.group("value"))
        entries.append(Entry(line_no, key, value, raw, True, ""))
    return entries


def scan(text: str) -> dict:
    entries = parse(text)
    seen: dict[str, int] = {}
    findings = []
    for entry in entries:
        if not entry.valid:
            findings.append({"line": entry.line, "key": None, "kind": "malformed", "detail": entry.issue})
            continue
        if entry.key in seen:
            findings.append({"line": entry.line, "key": entry.key, "kind": "duplicate", "detail": f"also defined on line {seen[entry.key]}"})
        else:
            seen[entry.key] = entry.line
        if not entry.value:
            findings.append({"line": entry.line, "key": entry.key, "kind": "empty", "detail": "value is empty"})
        if SENSITIVE.search(entry.key) and entry.value and not entry.value.startswith(("${", "$")):
            findings.append({"line": entry.line, "key": entry.key, "kind": "sensitive", "detail": "value redacted; review before sharing"})
    return {"entries": len(entries), "keys": sorted(seen), "findings": findings, "ok": not any(item["kind"] in {"malformed", "duplicate"} for item in findings)}


def redact(text: str, placeholder: str = "") -> str:
    output = []
    for raw in text.splitlines(keepends=True):
        match = ASSIGNMENT.match(raw)
        if not match:
            output.append(raw)
            continue
        key = match.group("key")
        newline = "\n" if raw.endswith("\n") else ""
        output.append(f"{match.group('prefix') or ''}{key}={placeholder}{newline}")
    return "".join(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Secret-safe .env inspection and redaction")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("file", type=Path)
    check.add_argument("--json", action="store_true", dest="as_json")
    redact_cmd = sub.add_parser("redact")
    redact_cmd.add_argument("file", type=Path)
    redact_cmd.add_argument("--output", type=Path, required=True)
    redact_cmd.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "check":
        result = scan(args.file.read_text(encoding="utf-8"))
        if args.as_json:
            print(json.dumps(result, indent=2))
        else:
            print(f"envsafe: {args.file} ({result['entries']} assignments)")
            for finding in result["findings"]:
                key = finding["key"] or "<line>"
                print(f"{finding['kind'].upper():9} line {finding['line']:4} {key}: {finding['detail']}")
            print("status: " + ("ok" if result["ok"] else "review required"))
        return 0 if result["ok"] else 1
    if args.output.exists() and not args.force:
        parser.error(f"refusing to overwrite {args.output}; use --force")
    args.output.write_text(redact(args.file.read_text(encoding="utf-8")), encoding="utf-8")
    print(f"wrote redacted example: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
