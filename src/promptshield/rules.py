"""Rule engine — map Surfaces to Findings via a YAML ruleset.

A rule is a regex (or several) plus metadata. The engine runs every rule's
patterns against every Surface's text; a match yields a :class:`Finding`. Rules
can be scoped to specific surface kinds (e.g. only commit messages) and can
require an extra "trigger" pattern so that, for example, a destructive verb only
fires when it co-occurs with agent-steering language — keeping false positives
down on ordinary imperative comments.

The packaged ruleset lives in ``rules.yaml`` next to this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from importlib import resources
from pathlib import Path

import yaml

from promptshield.collectors import Surface, SurfaceKind


class Severity(StrEnum):
    """Finding severity. HIGH findings make the CLI exit non-zero."""

    HIGH = "HIGH"
    MED = "MED"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"HIGH": 3, "MED": 2, "LOW": 1}[self.value]


# The five injection categories the plan names.
CATEGORIES = {
    "instruction_override",
    "data_destructive",
    "exfiltration",
    "tool_abuse",
    "obfuscation",
}

_EXCERPT_MAX = 160


@dataclass(frozen=True)
class Finding:
    """A single rule hit on a Surface."""

    rule_id: str
    severity: Severity
    category: str
    surface: SurfaceKind
    file: str
    line: int
    excerpt: str
    why: str

    def fingerprint_excerpt(self) -> str:
        """Normalized excerpt used for baseline fingerprinting."""
        return " ".join(self.excerpt.split()).lower()


@dataclass
class Rule:
    """A compiled detection rule."""

    id: str
    severity: Severity
    category: str
    why: str
    patterns: list[re.Pattern]
    requires: list[re.Pattern] = field(default_factory=list)
    surfaces: set[SurfaceKind] | None = None  # None = any surface
    # Which pack file this rule came from ("packaged" for the built-in set, or
    # the file path for a stacked pack). None for rules constructed in-process.
    source: str | None = None
    # False when a pack overrides a built-in to turn it off; disabled rules are
    # dropped from the active set by the loaders.
    enabled: bool = True

    def match(self, surface: Surface) -> Finding | None:
        """Return a Finding if this rule fires on ``surface``, else None."""
        if self.surfaces is not None and surface.kind not in self.surfaces:
            return None
        hit = next(
            (p.search(surface.text) for p in self.patterns
             if p.search(surface.text)),
            None,
        )
        if hit is None:
            return None
        if self.requires and not all(r.search(surface.text) for r in self.requires):
            return None
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            category=self.category,
            surface=surface.kind,
            file=surface.file,
            line=surface.line,
            excerpt=_make_excerpt(surface.text, hit),
            why=self.why,
        )


def _make_excerpt(text: str, match: re.Match) -> str:
    """Build a truncated excerpt centered on the matched span."""
    text = " ".join(text.split())
    if len(text) <= _EXCERPT_MAX:
        return text
    start = max(0, match.start() - _EXCERPT_MAX // 2)
    end = min(len(text), start + _EXCERPT_MAX)
    snippet = text[start:end]
    if start > 0:
        snippet = "…" + snippet
    if end < len(text):
        snippet = snippet + "…"
    return snippet


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _compile_patterns(value, *, flags: int) -> list[re.Pattern]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    return [re.compile(p, flags) for p in value]


def _parse_rule(raw: dict, *, source: str | None = None) -> Rule:
    if "id" not in raw:
        raise ValueError(f"rule missing required key 'id': {raw!r}")
    enabled = bool(raw.get("enabled", True))
    # A disable entry (enabled: false) only needs an id — it lets a pack turn
    # off a built-in rule without restating its full definition. We still build
    # a well-formed Rule (the value is irrelevant since it's dropped on load),
    # using benign placeholders so construction never fails.
    if not enabled:
        return Rule(
            id=raw["id"],
            severity=Severity.LOW,
            category=raw.get("category", "instruction_override"),
            why=raw.get("why", "disabled by pack"),
            patterns=_compile_patterns(raw.get("patterns"), flags=re.IGNORECASE),
            requires=_compile_patterns(raw.get("requires"), flags=re.IGNORECASE),
            surfaces=None,
            source=source,
            enabled=False,
        )
    for key in ("severity", "category", "why", "patterns"):
        if key not in raw:
            raise ValueError(f"rule missing required key '{key}': {raw!r}")
    category = raw["category"]
    if category not in CATEGORIES:
        raise ValueError(
            f"rule {raw['id']} has unknown category '{category}'"
        )
    flags = re.IGNORECASE
    if raw.get("multiline"):
        flags |= re.MULTILINE | re.DOTALL
    surfaces = raw.get("surfaces")
    surface_set = (
        {SurfaceKind(s) for s in surfaces} if surfaces else None
    )
    return Rule(
        id=raw["id"],
        severity=Severity(raw["severity"]),
        category=category,
        why=raw["why"],
        patterns=_compile_patterns(raw["patterns"], flags=flags),
        requires=_compile_patterns(raw.get("requires"), flags=flags),
        surfaces=surface_set,
        source=source,
        enabled=True,
    )


def _parse_pack(rules_raw: list[dict], *, source: str | None) -> list[Rule]:
    """Parse one pack's raw rule list, enforcing within-pack unique ids.

    Within a single pack, a repeated rule id is an error; across packs the same
    id is an override (handled by :func:`load_rule_packs`). Disabled rules are
    kept here so callers can decide; loaders drop them from the active set.
    """
    rules = [_parse_rule(r, source=source) for r in rules_raw]
    seen: set[str] = set()
    for r in rules:
        if r.id in seen:
            raise ValueError(f"duplicate rule id: {r.id}")
        seen.add(r.id)
    return rules


def _rules_raw_from(data: object) -> list[dict]:
    """Pull the ``rules`` list from a loaded YAML document."""
    rules_raw = data.get("rules", []) if isinstance(data, dict) else data
    if not isinstance(rules_raw, list):
        raise ValueError("ruleset must be a mapping with a 'rules' list")
    return rules_raw


def _load_packaged_rules() -> list[Rule]:
    """Load the packaged ``rules.yaml`` (``source='packaged'``)."""
    with resources.files("promptshield").joinpath("rules.yaml").open(
        "r", encoding="utf-8"
    ) as fh:
        data = yaml.safe_load(fh)
    rules_raw = _rules_raw_from(data)
    if not rules_raw:
        raise ValueError("no rules found in packaged rules.yaml")
    return _parse_pack(rules_raw, source="packaged")


def _load_pack_file(path: Path) -> list[Rule]:
    """Load a single ``.yaml`` pack file (``source=path``)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules_raw = _rules_raw_from(data)
    if not rules_raw:
        raise ValueError(f"no rules found in ruleset: {path}")
    return _parse_pack(rules_raw, source=str(path))


def _expand_pack_files(path: Path) -> list[Path]:
    """Expand a path to the ordered list of ``.yaml``/``.yml`` pack files.

    A directory is expanded to its YAML files in sorted order; a file is passed
    through unchanged.
    """
    if path.is_dir():
        return sorted(
            p
            for p in path.iterdir()
            if p.is_file() and p.suffix.lower() in {".yaml", ".yml"}
        )
    return [path]


def load_rules(path: str | Path | None = None) -> list[Rule]:
    """Load and compile rules from ``path`` or the packaged ``rules.yaml``.

    A rule with ``enabled: false`` is dropped from the returned active set.
    Behaves exactly as before for the single-path / packaged case.
    """
    if path is None:
        rules = _load_packaged_rules()
    else:
        rules = _load_pack_file(Path(path))
    return [r for r in rules if r.enabled]


def load_rule_packs(paths: list[str | Path] | None) -> list[Rule]:
    """Load the packaged ruleset first, then stack each path on top.

    Each path is either a ``.yaml`` file or a directory of ``.yaml``/``.yml``
    files loaded in sorted order. Packs stack in load order: a later pack
    overrides an earlier rule with the same id (last-wins), so a pack can
    narrow, broaden, or outright disable a built-in. A rule carrying
    ``enabled: false`` is removed from the active set. If ``paths`` is None or
    empty, returns the packaged ruleset (equivalent to :func:`load_rules`).
    """
    merged: dict[str, Rule] = {}
    for r in _load_packaged_rules():
        merged[r.id] = r
    if paths:
        for p in paths:
            for pack_file in _expand_pack_files(Path(p)):
                for r in _load_pack_file(pack_file):
                    merged[r.id] = r  # override (last-wins)
    return [r for r in merged.values() if r.enabled]


def run_rules(surfaces: list[Surface], rules: list[Rule]) -> list[Finding]:
    """Run every rule against every surface, returning all Findings."""
    findings: list[Finding] = []
    for surface in surfaces:
        for rule in rules:
            finding = rule.match(surface)
            if finding is not None:
                findings.append(finding)
    findings.sort(key=lambda f: (-f.severity.rank, f.file, f.line, f.rule_id))
    return findings
