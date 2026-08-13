# Contributing

Thanks for your interest in open80211! This project is a security testing
suite. Please read [SECURITY.md](SECURITY.md) and keep responsible-use
principles in mind.

## Getting started

```bash
pip install -r requirements.txt
python -m compileall -q .          # syntax check
python test_end_to_end.py          # core crypto path
python test_advanced.py            # WEP / NTLMv2 / TLS CA / exports / report
```

## Development guidelines

* **Style**: PEP 8, ~100 char lines, type hints on public functions.
* **No new comments unless they explain non-obvious logic** (project convention).
* Match existing patterns — modules in `open80211/modules/`, helpers in
  `open80211/core/`, UI via `core/ui.py` (never raw `print` for the menu).
* Keep everything import-safe on **Windows dev boxes** while guarding
  wireless/injection features behind Linux + privilege checks.
* Never add absolute paths or machine-specific values.

## Testing

* Both test scripts must pass on every PR. They build synthetic traffic —
  no real network access required.
* Any new crypto or wire-format parsing must get a round-trip test in
  `test_advanced.py` or `test_end_to_end.py`.

## Before opening a PR

1. `python -m compileall -q .`
2. Run both test scripts.
3. Run `python open80211.py --version`.
4. Ensure no captures, hashes, credentials, or `results/` artifacts are
   committed (`.gitignore` covers these).

## Commit style

* One logical change per commit; imperative subject line; explain the *why*
  in the body when non-obvious.
