<div align="center">

# 📐 sigma-rule-pack

**A small, curated pack of [Sigma](https://github.com/SigmaHQ/sigma) detection rules — with its own validator.**
Generic, vendor-neutral detections for Windows, Linux and AWS CloudTrail, each mapped to MITRE ATT&CK,
plus `sigma-lint`: a dependency-light checker that keeps every rule well-formed in CI.

[![CI](https://github.com/bvlik/sigma-rule-pack/actions/workflows/ci.yml/badge.svg)](https://github.com/bvlik/sigma-rule-pack/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10+-0A1929?style=for-the-badge&logo=python&logoColor=12ABDB)
![Sigma](https://img.shields.io/badge/Format-Sigma-0070AD?style=for-the-badge)

</div>

---

## Why

Detection content rots silently: a typo in a `condition`, a duplicated `id` or a missing
`logsource` only shows up when the rule fails to load in your SIEM. This repo pairs a set of
hand-written rules with a linter so the pack stays valid on every commit — the same
`sigma-lint` step runs in CI against `rules/`.

> 🛡️ **Defensive content.** The rules describe attacker behaviour in order to *detect* it.

## Rules

| Platform | Rule | ATT&CK | Level |
|----------|------|--------|-------|
| Windows | LSASS dump via `comsvcs.dll` MiniDump | T1003.001 | High |
| Windows | `whoami` account discovery | T1033 | Low |
| Linux | Bash `/dev/tcp` reverse shell | T1059.004 | High |
| Linux | SSH password brute force | T1110 | Medium |
| AWS | CloudTrail logging disabled | T1562.008 | High |
| AWS | Root account console login | T1078.004 | High |

## sigma-lint

```bash
pip install -r requirements.txt

# Validate the whole pack (recurses *.yml / *.yaml)
python -m sigmalint rules/

# Or a single file / your own directory
python -m sigmalint rules/cloud/aws_root_console_login.yml
```

It checks each rule for: a non-empty `title`, a valid UUID `id`, an allowed `level`,
a `logsource` with at least one of product/service/category, a `detection` block whose
`condition` only references selections that exist — and flags duplicate ids across the pack.
Exit code is non-zero on any error, so it drops straight into a pipeline.

## Layout

```
rules/<platform>/<rule>.yml   the detections
src/sigmalint/validate.py     pure validation logic (unit-tested)
src/sigmalint/cli.py          YAML loading + reporting + exit code
```

## Roadmap
- [ ] Backend conversion examples (Splunk SPL / Elastic) via `sigma` CLI
- [ ] More cloud coverage (Azure sign-in logs, GuardDuty)
- [ ] `field`/modifier sanity checks per logsource
