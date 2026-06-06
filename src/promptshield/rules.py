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


def _parse_rule(raw: dict) -> Rule:
    for key in ("id", "severity", "category", "why", "patterns"):
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
    )


def load_rules(path: str | Path | None = None) -> list[Rule]:
    """Load and compile rules from ``path`` or the packaged ``rules.yaml``."""
    if path is None:
        with resources.files("promptshield").joinpath("rules.yaml").open(
            "r", encoding="utf-8"
        ) as fh:
            data = yaml.safe_load(fh)
    else:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rules_raw = data.get("rules", []) if isinstance(data, dict) else data
    if not rules_raw:
        raise ValueError(f"no rules found in ruleset: {path or 'rules.yaml'}")
    rules = [_parse_rule(r) for r in rules_raw]
    seen: set[str] = set()
    for r in rules:
        if r.id in seen:
            raise ValueError(f"duplicate rule id: {r.id}")
        seen.add(r.id)
    return rules


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
