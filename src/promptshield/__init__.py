"""PromptShield — scan code your AI coding agent reads, before it obeys it.

PromptShield treats source text an agent will *read* (comments, docstrings,
markdown, string literals, commit messages) as a prompt-injection attack
surface, decomposing a repo or diff into ``Surface`` records and mapping each
to zero-or-more ``Finding`` records via a YAML rule engine.
"""

from promptshield.collectors import Surface, SurfaceKind
from promptshield.rules import Finding, Rule, Severity

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "Finding",
    "Rule",
    "Severity",
    "Surface",
    "SurfaceKind",
]
