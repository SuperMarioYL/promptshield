"""Rule.match searches each pattern once per surface.

quality-rule-match-double-search (v0.17.0): ``Rule.match`` built
``next((p.search(text) for p in patterns if p.search(text)), None)`` — the
pattern that matches is searched TWICE (once in the generator's filter, once
for the yielded value). That is a flat 2x regex cost on the scanner's hottest
loop (surfaces x rules x patterns). The rewrite keeps first-match-wins
semantics while searching each pattern at most once.
"""

from __future__ import annotations

import re

from promptshield.collectors import Surface, SurfaceKind
from promptshield.rules import Rule, Severity


class _CountingPattern:
    """Duck-typed stand-in for ``re.Pattern`` that counts ``search`` calls."""

    def __init__(self, pattern: str) -> None:
        self.re = re.compile(pattern)
        self.searches = 0

    def search(self, text: str):
        self.searches += 1
        return self.re.search(text)


def _surface(text: str = "hello world") -> Surface:
    return Surface(text=text, file="t.py", line=1, kind=SurfaceKind.COMMENT)


def _rule(patterns: list[_CountingPattern], requires=None) -> Rule:
    return Rule(
        id="PS-test",
        severity=Severity.HIGH,
        category="instruction_override",
        why="test rule",
        patterns=patterns,  # type: ignore[arg-type]
        requires=requires or [],
    )


def test_each_pattern_searched_once_until_first_hit():
    first = _CountingPattern("hello")
    second = _CountingPattern("world")
    finding = _rule([first, second]).match(_surface())
    assert finding is not None
    assert (first.searches, second.searches) == (1, 0)


def test_each_non_matching_pattern_searched_once():
    first = _CountingPattern("absent")
    second = _CountingPattern("also-absent")
    third = _CountingPattern("world")
    finding = _rule([first, second, third]).match(_surface())
    assert finding is not None
    assert (first.searches, second.searches, third.searches) == (1, 1, 1)


def test_first_matching_pattern_still_wins_for_excerpt():
    first = _CountingPattern("hello")
    second = _CountingPattern("world")
    finding = _rule([first, second]).match(_surface())
    assert finding is not None
    assert finding.excerpt == "hello world"
    assert (first.searches, second.searches) == (1, 0)


def test_surface_kind_filter_still_short_circuits():
    pattern = _CountingPattern("hello")
    rule = Rule(
        id="PS-test",
        severity=Severity.HIGH,
        category="instruction_override",
        why="test rule",
        patterns=[pattern],  # type: ignore[arg-type]
        surfaces={SurfaceKind.DOCSTRING},
    )
    assert rule.match(_surface()) is None
    assert pattern.searches == 0
