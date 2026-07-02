# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Opt-in semantic detection layered on top of the regex / heuristic engine.
- Managed attack-signature / rule feed (PromptShield Cloud).
- GitHub Marketplace listing.

## [0.2.0] - 2026-07-02

The release that lands PromptShield findings inside GitHub itself: SARIF
output uploads to the repo's Security → Code scanning tab, rule packs stack so
teams can layer their own policy on top of the seed ruleset, and an
obfuscation decode pass catches injections hidden behind a layer of encoding.

### Added

#### m4 — SARIF output

- `promptshield scan --format sarif` emits a SARIF 2.1.0 log consumable by
  GitHub code scanning.
- The bundled GitHub Action uploads the SARIF via
  `github/codeql-action/upload-sarif@v3`, so findings appear in the repo's
  Security → Code scanning tab — not just a red check. The upload runs even
  when a HIGH finding makes the scan exit 1.

#### m5 — stackable rule packs

- `--rules` is repeatable and accepts a directory of `rules.yaml` files; packs
  stack on top of the built-in seed ruleset in load order, last-wins by rule
  id, so a pack can narrow, broaden, or outright disable a built-in.
- Rules carry an `enabled` flag — a pack can set `enabled: false` to turn a
  built-in rule off (a disable entry only needs an `id`).
- `promptshield rules list` prints the active merged ruleset (one row per
  rule, including its `enabled` state).

#### m6 — obfuscation decode pass

- base64 / hex / zero-width-stripped / homoglyph-normalized variants of every
  surface are re-scanned, so an injection hidden behind one encoding layer is
  still caught.
- `--no-decode` opts out of the decode pass for repos that want byte-exact
  scanning.

### Fixed

#### m7 — comment-marker leak in `_strip_line_comment`

- `_strip_line_comment` no longer leaks the real comment marker (e.g. `//`)
  into extracted text when a statement terminator precedes the comment; `;`
  was dropped from the default line-comment markers. Previously this
  corrupted excerpts and baseline fingerprints.

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

[Unreleased]: https://github.com/SuperMarioYL/promptshield/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SuperMarioYL/promptshield/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/promptshield/releases/tag/v0.1.0
