# envsafe: Safe `.env` Inspection and Redaction

[![CI](https://github.com/varungor365/envsafe/actions/workflows/ci.yml/badge.svg)](https://github.com/varungor365/envsafe/actions/workflows/ci.yml)

**Inspect, validate, and redact `.env` files without printing secret values.**

`envsafe` is a local-first command-line tool for the small but expensive mistakes around environment files: duplicate keys, malformed lines, missing values, and accidentally sharing live credentials. It preserves comments and key names when producing a safe `.env.example`.

## Common workflows

- Check a local `.env` before attaching diagnostics to an issue.
- Generate a reviewable `.env.example` without copying live values.
- Add a secret-safe pre-commit or CI metadata check.

## Why this exists

Environment files are useful for local development but easy to leak into logs, pull requests, examples, and support bundles. `envsafe` keeps the workflow local and reports metadata instead of values, so a maintainer can check `.env` hygiene without sending credentials to a service.

| Use case | Command |
|---|---|
| Inspect a local environment file | `envsafe check .env` |
| Create a reviewable report | `envsafe check .env --json` |
| Generate a safe template | `envsafe redact .env --output .env.example` |
| Use in CI or a pre-commit hook | Run `envsafe check .env --json` and apply your own exit policy |

## Three-minute quick start

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install envsafe
envsafe check .env
envsafe redact .env --output .env.example
```

The default output never prints values. It reports key names, line numbers, and redacted findings. `redact` refuses to overwrite an existing file unless `--force` is supplied.

## What it catches

The parser understands comments, `export KEY=value`, quoted values, inline comments, empty values, duplicate keys, and malformed assignments. It flags likely secret-bearing keys without trying to prove whether a value is valid. It does not contact an API, validate credentials, or upload your file.

## Safe defaults and limitations

`envsafe` never prints parsed values in its normal findings and performs no network access. Treat the input `.env` file as sensitive anyway, because other commands or shells may record their own arguments and output. The tool identifies likely problems; it does not prove that a value is a credential, detect every encoding or secret format, rotate credentials, or replace repository secret scanning. Review the generated `.env.example` before committing it.

## Why star this repository?

Star this project if you share `.env.example` files, maintain local-development setups, review pull requests for secret leaks, or want a lightweight secret-safe utility that works locally, in CI, and in pre-commit hooks.

## Development

```bash
git clone https://github.com/varungor365/envsafe
cd envsafe
python -m pip install -e '.[dev]'
pytest -q
```

## License

MIT. See [LICENSE](LICENSE).
