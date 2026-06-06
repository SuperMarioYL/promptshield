# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Opt-in semantic detection layered on top of the regex / heuristic engine.
- Managed attack-signature / rule feed (PromptShield Cloud).
- GitHub Marketplace listing.

## [0.1.0] - 2026-06-06

First public release. Scans the source text a coding agent reads — comments,
docstrings, commit messages, markdown, config, and string literals — as a
prompt-injection attack surface, before the agent ingests it.

### Added

#### m1 — repo scan (`scan_repo`)

- `promptshield scan <path>` walks a directory, extracts comments, docstrings,
  markdown, config, and string literals into `Surface` records.
- YAML-driven rule engine (`rules.yaml`) with a seed ruleset of ~12 rules
  across the five categories: `instruction_override`, `data_destructive`,
  `exfiltration`, `tool_abuse`, `obfuscation`.
- Rich findings table with a per-severity summary; `--json` for machine output;
  `--no-color` for plain CI logs.
- `requires` second-gate clause on noisy rules to keep false positives low.
- Exit code `0` when no HIGH findings, `1` when any HIGH is present.

#### m2 — diff & CI (`diff_and_ci`)

- `promptshield scan --diff <ref>` parses `git diff` and scans only added lines
  plus new commit messages.
- `promptshield scan --pr <file.json>` parses a `gh api .../files` PR-files JSON
  document.
- `.github/workflows/promptshield.yml` GitHub Action that gates every PR and
  turns the check red on a HIGH finding.
- `--rules FILE` to supply a custom ruleset; `--repo DIR` for `--diff`.

#### m3 — baseline & demo (`baseline_and_demo`)

- `.promptshield-baseline.yaml` suppression by fingerprint
  (`rule_id` + file + excerpt hash); `--update-baseline` writes the baseline.
- `tests/fixtures/malicious_pr/` reproduces the real r/LocalLLaMA data-nuking
  prompt-injection attack (hidden `rm -rf` + exfiltration in a comment and a
  docstring).
- asciinema demo assets (`assets/demo.tape`, `assets/demo.svg`).
- Bilingual README (Chinese primary `README.md`, English `README.en.md`).

[Unreleased]: https://github.com/SuperMarioYL/promptshield/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SuperMarioYL/promptshield/releases/tag/v0.1.0
