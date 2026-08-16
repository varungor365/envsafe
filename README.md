# envsafe

**Inspect, validate, and redact `.env` files without printing secrets.**

`envsafe` is a local-first CLI for the small but expensive mistakes around environment files: duplicate keys, malformed lines, missing values, and accidentally sharing live credentials. It preserves comments and key names when producing a safe `.env.example`.

## Quick start

```bash
pipx install envsafe
envsafe check .env
envsafe check .env --json
envsafe redact .env --output .env.example
```

The default output never prints values. It reports key names, line numbers, and redacted findings. `redact` refuses to overwrite an existing file unless `--force` is supplied.

## What it catches

The parser understands comments, `export KEY=value`, quoted values, inline comments, empty values, duplicate keys, and malformed assignments. It flags likely secret-bearing keys without trying to prove whether a value is valid. It does not contact an API, validate credentials, or upload your file.

## Why star this repository

Star this project if you share `.env.example` files, maintain local-development setups, review pull requests for secret leaks, or want a lightweight secret-safe utility that works in CI and pre-commit hooks.

## Development

```bash
git clone https://github.com/varungor365/envsafe
cd envsafe
python -m pip install -e ".[dev]"
pytest -q
```

## License

MIT.
