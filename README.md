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

**16 rules** across Windows, Linux and AWS CloudTrail, every one mapped to MITRE ATT&CK.

| Platform | Rule | ATT&CK | Level |
|----------|------|--------|-------|
| Windows | LSASS dump via `comsvcs.dll` MiniDump | T1003.001 | High |
| Windows | Encoded PowerShell command | T1059.001 | Medium |
| Windows | Registry Run key persistence | T1547.001 | Medium |
| Windows | Volume Shadow Copy deletion | T1490 | High |
| Windows | PsExec service installation | T1569.002 | Medium |
| Windows | `whoami` account discovery | T1033 | Low |
| Linux | Bash `/dev/tcp` reverse shell | T1059.004 | High |
| Linux | Remote script piped to shell (`curl|bash`) | T1059.004 | High |
| Linux | SSH password brute force | T1110 | Medium |
| Linux | Cron job persistence | T1053.003 | Medium |
| Linux | Shell history tampering | T1070.003 | Medium |
| AWS | CloudTrail logging disabled | T1562.008 | High |
| AWS | GuardDuty disabled | T1562.008 | High |
| AWS | Root account console login | T1078.004 | High |
| AWS | IAM backdoor user / access key | T1136.003 | Medium |
| AWS | Security group opened to `0.0.0.0/0` | T1562.007 | Medium |

```bash
python -m sigmalint --stats rules/      # counts by level / platform
```

## sigma-lint

```bash
pip install -r requirements.txt

# Validate the whole pack (recurses *.yml / *.yaml)
python -m sigmalint rules/

# Or a single file / your own directory
python -m sigmalint rules/cloud/aws_root_console_login.yml
```

Each rule is checked for:
- a non-empty `title` (unique across the pack) and a valid UUID `id` (unique across the pack);
- an allowed `level` and `status`;
- a `logsource` with at least one of product/service/category;
- a `detection` block whose `condition` only references selections that exist
  (aggregation after `|` is ignored);
- **pack quality gates**: a `description`, an `author`, at least one `references` URL,
  a `YYYY/MM/DD` `date`, and well-formed `attack.tNNNN[.NNN]` ATT&CK tags.

Exit code is non-zero on any error, so it drops straight into a pipeline.

## Backend conversion

`sigma-lint` ships a small, dependency-free backend that turns a rule's `detection`
block into a query for your SIEM — no `sigma` CLI or `pySigma` install required:

```bash
# Splunk SPL
python -m sigmalint --convert splunk rules/

# Elastic (Lucene query string)
python -m sigmalint --convert elastic rules/cloud/aws_iam_backdoor_user.yml
```

```spl
# AWS IAM Backdoor User or Access Key
search (eventSource="iam.amazonaws.com" AND (eventName="CreateUser" OR eventName="CreateAccessKey" OR eventName="CreateLoginProfile"))

# SSH Password Brute Force
search ("Failed password for" OR ...) | stats count by src_ip | where count > 10
```

Supported: `contains` / `startswith` / `endswith` / equality modifiers (and the
`|all` list-AND modifier), `and`/`or`/`not`, parentheses, the `all of` / `1 of` /
`any of` quantifiers, and `count() by … > N` aggregations (mapped to `stats … | where`
for Splunk). Anything the backend can't express faithfully **fails loudly** rather than
emitting a silently-wrong query — and the CI converts the whole pack to both backends as a
self-check.

## Layout

```
rules/<platform>/<rule>.yml   the detections
src/sigmalint/validate.py     pure validation logic (unit-tested)
src/sigmalint/convert.py      pure Sigma -> Splunk/Elastic backend (unit-tested)
src/sigmalint/cli.py          YAML loading + reporting + exit code
```

## Roadmap
- [x] Pack quality gates (description/author/references/date/ATT&CK tags)
- [x] Duplicate id **and** title detection, `--stats` summary
- [x] Backend conversion (Splunk SPL / Elastic Lucene), no external deps
- [ ] More cloud coverage (Azure sign-in logs, GCP audit logs)
- [ ] `field`/modifier sanity checks per logsource
