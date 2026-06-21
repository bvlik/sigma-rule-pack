# Contributing

Detection rules and a small validator. Everything here is **defensive**: the rules
describe attacker behaviour to *detect*, and the linter only reads YAML.

## Dev setup
```bash
pip install -r requirements.txt
pip install pytest ruff bandit
```

## Before opening a PR
- `ruff check .` — lint
- `bandit -r src` — security scan
- `python -m compileall src` — syntax
- `PYTHONPATH=src pytest -q` — validator unit tests
- `PYTHONPATH=src python -m sigmalint rules/` — validate every rule (CI runs this too)

## Adding a rule
- One rule per `.yml` file under `rules/<platform>/`.
- Required: `title`, a UUID `id` (use `python -c "import uuid;print(uuid.uuid4())"`),
  `level`, a `logsource` with at least one of product/service/category, and a
  `detection` block with selections and a `condition`.
- Map to MITRE ATT&CK via `tags:` and cite a `references:` URL.
- Keep `author: Bvlik`.

## Conventions
- Conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`)
- ASCII-only CLI output (`[PASS]` / `[REJECT]`) so it runs cleanly on Windows.
