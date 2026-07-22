"""Collectors — decompose a repo, a git diff, or a PR-files JSON into Surfaces.

A ``Surface`` is one chunk of source text the coding agent will *read*: a code
comment, a docstring, a markdown line, a string literal, or a commit message.
The rule engine runs over these records, never over raw bytes, so that a
"delete the cache" instruction inside a comment is treated differently from the
same words inside executable code we never claim to understand.

Three collection modes (all return ``list[Surface]``):

* :func:`collect_path`    — walk a directory or read a single file.
* :func:`collect_diff`    — parse ``git diff`` *added* lines for a ref.
* :func:`collect_pr_json` — parse ``gh api`` PR-files JSON (filename + patch).

No network calls happen here. ``git`` is shelled out only for ``--diff``; the
PR-JSON path is fully offline (the caller is expected to pipe ``gh`` output in).
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

# ---------------------------------------------------------------------------
# Surface model
# ---------------------------------------------------------------------------


class SurfaceKind(StrEnum):
    """The kind of code-as-prompt surface a Surface was extracted from."""

    COMMENT = "comment"
    DOCSTRING = "docstring"
    COMMIT_MSG = "commit_msg"
    MARKDOWN = "markdown"
    CONFIG = "config"
    STRING_LITERAL = "string_literal"


@dataclass(frozen=True)
class Surface:
    """One readable chunk of source text plus where it came from.

    ``decoded_from`` is set only on surfaces produced by the decode pass
    (``decode.py``); it records the encoding layer the text was recovered from
    so downstream reporting can attribute a finding to, e.g., a base64 blob
    rather than the visible text. It defaults to ``None`` so every existing
    ``Surface(...)`` construction stays valid.
    """

    text: str
    file: str
    line: int
    kind: SurfaceKind
    decoded_from: str | None = None


# ---------------------------------------------------------------------------
# File classification
# ---------------------------------------------------------------------------

# Extensions we treat as text and try to extract surfaces from. Anything else
# (binaries, images, lockfiles we don't care about) is skipped.
TEXT_EXTENSIONS = {
    ".py", ".pyi",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".c", ".h", ".cpp", ".hpp", ".cc",
    ".rb", ".php", ".sh", ".bash", ".zsh",
    ".md", ".markdown", ".rst", ".txt",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".json",
}

MARKDOWN_EXTENSIONS = {".md", ".markdown", ".rst", ".txt"}
CONFIG_EXTENSIONS = {".yaml", ".yml", ".toml", ".ini", ".cfg", ".json"}

# Directories never worth scanning.
SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".tox", ".idea", ".vscode",
}

# Files never worth scanning by basename. The baseline file stores each accepted
# finding's excerpt verbatim; scanning it re-flags those excerpts on the baseline
# file itself, and because the finding's ``file`` is now the baseline path (not
# the original) the fingerprint differs and baseline suppression never fires — so
# the very next scan after ``--update-baseline`` is noisy (m9). We hardcode the
# basename here rather than importing ``DEFAULT_BASELINE_NAME`` from
# ``promptshield.baseline`` to avoid a collectors↔baseline import cycle
# (baseline → rules → collectors).
SKIP_FILES = {
    ".promptshield-baseline.yaml",
}

MAX_FILE_BYTES = 1_000_000  # skip files larger than ~1 MB

# ---------------------------------------------------------------------------
# Comment / docstring / string-literal extraction
# ---------------------------------------------------------------------------

# Single-line comment markers by "family". We keep this deliberately broad and
# language-agnostic — the plan is explicit: line + comment-block scanning, no
# per-language AST. The semicolon is intentionally NOT here: it ends statements
# in C-family languages but is rarely a genuine line-comment starter, and
# treating it as one leaked the real `//` marker into extracted excerpts (m7).
_LINE_COMMENT_MARKERS = ("#", "//", "--")

# Inline block-comment delimiters (start, end) handled on a per-line basis.
_BLOCK_COMMENT_PAIRS = (
    ("/*", "*/"),
    ("<!--", "-->"),
)

# Triple-quoted docstring / multiline-string delimiters.
_TRIPLE_QUOTES = ('"""', "'''")

# A quoted string literal on a single line (handles escaped quotes crudely).
_STRING_LITERAL_RE = re.compile(r"""(['"])((?:\\.|(?!\1).)*)\1""")


def _in_open_string(prefix: str) -> bool:
    """True if ``prefix`` ends inside an unclosed single/double-quoted string.

    Walks the prefix tracking quote state so a comment marker is only skipped
    when it genuinely sits inside an open string. The old implementation used a
    crude per-quote parity count (``prefix.count("'") % 2``), which counted
    apostrophes *inside* a double-quoted string — so ``msg = "don't"  # …`` was
    misread as having an open ``'`` string and the ``#`` comment was dropped
    entirely, silently un-scanning the injection (m8). This walk respects the
    active delimiter and backslash escapes; it is not an AST, so it stays within
    the v0.1 "no per-language parser" scope.
    """
    quote: str | None = None
    escaped = False
    for ch in prefix:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            # A backslash escapes the next char only while inside a string.
            if quote is not None:
                escaped = True
            continue
        if quote is None:
            if ch == '"' or ch == "'":
                quote = ch
        else:
            if ch == quote:
                quote = None
    return quote is not None


def _find_line_comment(line: str) -> tuple[int, str] | None:
    """Return ``(marker_index, comment_text)`` for ``line``'s earliest comment.

    ``marker_index`` is where the winning marker starts in ``line`` so callers
    can still scan the *code before it* — a trailing comment must never shadow a
    prose string literal sitting in the preceding code (m13). Returns ``None``
    when no marker sits outside an open string.

    Picks the earliest marker position, but remembers *which* marker matched at
    that position so slicing uses the correct marker length even when markers
    overlap (m7: previously the marker was re-derived by scanning the marker
    list in order, which could pick the wrong length and leak the real marker
    into the excerpt).
    """
    best: int | None = None
    best_marker: str | None = None
    for marker in _LINE_COMMENT_MARKERS:
        idx = line.find(marker)
        if idx == -1:
            continue
        # Avoid flagging the marker when it's genuinely inside a quoted string.
        # A quote-state walk over the prefix (m8) — NOT a per-quote parity count,
        # which mis-classified apostrophes inside double-quoted strings and
        # dropped legitimate comments (and let an attacker hide an injection by
        # prefixing the comment with any apostrophe-bearing string literal).
        if _in_open_string(line[:idx]):
            continue
        if best is None or idx < best:
            best = idx
            best_marker = marker
    if best is None or best_marker is None:
        return None
    return best, line[best + len(best_marker) :].strip()


def _strip_line_comment(line: str) -> str | None:
    """Return the comment text of ``line`` if it contains a line comment.

    Thin wrapper over :func:`_find_line_comment` for callers that only need the
    comment body.
    """
    found = _find_line_comment(line)
    return found[1] if found is not None else None


def _extract_string_literals(line: str) -> list[str]:
    """Return quoted string-literal contents on ``line`` (non-trivial only)."""
    out: list[str] = []
    for _, body in _STRING_LITERAL_RE.findall(line):
        body = body.strip()
        # Only keep literals that look like prose — they're the ones that can
        # carry hidden instructions. Skip short / pathy / format-string noise.
        if len(body) >= 12 and " " in body:
            out.append(body)
    return out


def extract_surfaces_from_text(
    text: str,
    file: str,
    *,
    kind_for_whole_file: SurfaceKind | None = None,
    base_line: int = 1,
) -> list[Surface]:
    """Extract Surfaces from a blob of source ``text``.

    ``kind_for_whole_file`` forces every line to a single kind (used for
    markdown / config files where the whole document is readable prose).
    Otherwise we extract comments, triple-quoted blocks, and string literals.
    ``base_line`` lets diff collectors offset reported line numbers.
    """
    surfaces: list[Surface] = []
    lines = text.splitlines()

    # Whole-file prose modes (markdown, config) — every non-blank line counts.
    if kind_for_whole_file is not None:
        for i, raw in enumerate(lines):
            stripped = raw.strip()
            if stripped:
                surfaces.append(
                    Surface(
                        text=stripped,
                        file=file,
                        line=base_line + i,
                        kind=kind_for_whole_file,
                    )
                )
        return surfaces

    # Source-code mode: comments + docstrings + string literals.
    in_triple: str | None = None
    triple_start_line = 0
    triple_buf: list[str] = []
    in_block: tuple[str, str] | None = None

    for i, raw in enumerate(lines):
        lineno = base_line + i

        # --- inside a triple-quoted docstring/string ---
        if in_triple is not None:
            closer = in_triple
            end = raw.find(closer)
            if end == -1:
                triple_buf.append(raw)
                continue
            triple_buf.append(raw[:end])
            doc = "\n".join(triple_buf).strip()
            if doc:
                surfaces.append(
                    Surface(doc, file, triple_start_line, SurfaceKind.DOCSTRING)
                )
            in_triple = None
            triple_buf = []
            # fall through to scan the remainder of the line below
            raw = raw[end + len(closer) :]

        # --- inside a multi-line block comment ---
        if in_block is not None:
            _, closer = in_block
            end = raw.find(closer)
            if end == -1:
                body = raw.strip()
                if body:
                    surfaces.append(
                        Surface(body, file, lineno, SurfaceKind.COMMENT)
                    )
                continue
            body = raw[:end].strip()
            if body:
                surfaces.append(Surface(body, file, lineno, SurfaceKind.COMMENT))
            in_block = None
            raw = raw[end + len(closer) :]

        # --- start of a triple-quoted block? ---
        opened_triple = False
        for q in _TRIPLE_QUOTES:
            idx = raw.find(q)
            if idx == -1:
                continue
            # Code before the opening triple-quote can still carry a prose string
            # literal with an injection; scan it before the rest is consumed (m13).
            for lit in _extract_string_literals(raw[:idx]):
                surfaces.append(
                    Surface(lit, file, lineno, SurfaceKind.STRING_LITERAL)
                )
            rest = raw[idx + len(q) :]
            close = rest.find(q)
            if close != -1:
                # single-line triple-quoted string
                doc = rest[:close].strip()
                if doc:
                    surfaces.append(
                        Surface(doc, file, lineno, SurfaceKind.DOCSTRING)
                    )
            else:
                in_triple = q
                triple_start_line = lineno
                triple_buf = [rest]
            opened_triple = True
            break
        if opened_triple:
            continue

        # --- start of a block comment? ---
        opened_block = False
        for opener, closer in _BLOCK_COMMENT_PAIRS:
            idx = raw.find(opener)
            if idx == -1:
                continue
            # Code before an inline block comment must still be scanned for a
            # prose string literal before that prefix is dropped (m13).
            for lit in _extract_string_literals(raw[:idx]):
                surfaces.append(
                    Surface(lit, file, lineno, SurfaceKind.STRING_LITERAL)
                )
            rest = raw[idx + len(opener) :]
            close = rest.find(closer)
            if close != -1:
                body = rest[:close].strip()
                if body:
                    surfaces.append(
                        Surface(body, file, lineno, SurfaceKind.COMMENT)
                    )
                raw = rest[close + len(closer) :]
            else:
                body = rest.strip()
                if body:
                    surfaces.append(
                        Surface(body, file, lineno, SurfaceKind.COMMENT)
                    )
                in_block = (opener, closer)
                opened_block = True
                break
        if opened_block:
            continue

        # --- line comment? ---
        found_comment = _find_line_comment(raw)
        if found_comment is not None:
            marker_idx, comment = found_comment
            # A trailing comment must not shadow a prose string literal sitting in
            # the code *before* it (m13): previously reaching a line comment
            # `continue`d straight past string-literal extraction, so
            # `BANNER = "ignore all previous instructions"  # label` yielded only
            # the (benign) comment surface and the injection in the literal was
            # never scanned — a one-character evasion (append any comment).
            for lit in _extract_string_literals(raw[:marker_idx]):
                surfaces.append(
                    Surface(lit, file, lineno, SurfaceKind.STRING_LITERAL)
                )
            if comment:
                surfaces.append(
                    Surface(comment, file, lineno, SurfaceKind.COMMENT)
                )
            continue

        # --- prose-like string literals ---
        for lit in _extract_string_literals(raw):
            surfaces.append(
                Surface(lit, file, lineno, SurfaceKind.STRING_LITERAL)
            )

    # An unterminated triple-quote (truncated file / diff hunk) — flush it.
    if in_triple is not None and triple_buf:
        doc = "\n".join(triple_buf).strip()
        if doc:
            surfaces.append(
                Surface(doc, file, triple_start_line, SurfaceKind.DOCSTRING)
            )

    return surfaces


def _kind_for_path(path: Path) -> SurfaceKind | None:
    """Return a whole-file SurfaceKind for prose files, else None (code mode)."""
    ext = path.suffix.lower()
    if ext in MARKDOWN_EXTENSIONS:
        return SurfaceKind.MARKDOWN
    if ext in CONFIG_EXTENSIONS:
        return SurfaceKind.CONFIG
    return None


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


# ---------------------------------------------------------------------------
# Mode 1: walk a path
# ---------------------------------------------------------------------------


def collect_file(path: Path, *, display: str | None = None) -> list[Surface]:
    """Extract Surfaces from a single file."""
    text = _read_text(path)
    if text is None:
        return []
    name = display if display is not None else str(path)
    return extract_surfaces_from_text(
        text, name, kind_for_whole_file=_kind_for_path(path)
    )


def collect_path(root: str | Path) -> list[Surface]:
    """Walk ``root`` (file or directory) and collect Surfaces from text files."""
    root = Path(root)
    if root.is_file():
        rel = root.name
        return collect_file(root, display=rel)

    surfaces: list[Surface] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        # Skip only genuine SKIP_DIRS *subdirectories*. ``path.parts`` includes
        # the scan root and every ancestor directory, so a scan root (or any
        # parent dir) literally named ``build`` / ``venv`` / ``dist`` / etc.
        # would skip EVERY file — a silent full false-negative on the primary
        # ``scan <dir>`` use case, triggered by nothing more than a common
        # directory name (fix-skipdirs-ignores-scan-root). Test the directory
        # components RELATIVE to the scan root (which exclude the root and its
        # ancestors); ``[:-1]`` drops the file's own name so only real
        # subdirectory components can trigger a skip, while a scan root or an
        # ancestor named ``build`` cannot — genuine ``build``/``node_modules``
        # subdirectories still are.
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            rel_parts = path.parts
        if any(part in SKIP_DIRS for part in rel_parts[:-1]):
            continue
        if path.name in SKIP_FILES:  # m9 — never re-scan our own baseline file
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        try:
            display = str(path.relative_to(root))
        except ValueError:
            display = str(path)
        surfaces.extend(collect_file(path, display=display))
    return surfaces


# ---------------------------------------------------------------------------
# Mode 2: git diff (added lines only)
# ---------------------------------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_unified_diff(diff_text: str) -> list[Surface]:
    """Parse a unified diff and extract Surfaces from *added* lines only.

    We reconstruct each file's added lines (with their new line numbers) and run
    the per-file surface extractor on that reconstructed fragment. Removed and
    context lines are ignored — we only care about what the agent will newly
    read after the change lands.
    """
    surfaces: list[Surface] = []
    current_file: str | None = None
    added: list[tuple[int, str]] = []
    new_lineno = 0
    # Track whether we're inside a hunk body so a ``+++ `` file-header check
    # can't fire on an ADDED line whose content merely begins with ``++`` (m10):
    # git emits such a line as ``+++ some heading`` (the leading ``+`` of the
    # added line plus the ``++`` of its content), which is indistinguishable from
    # a real ``+++ b/file`` header without hunk state. Real file headers only
    # appear OUTSIDE a hunk (before the first ``@@``); inside a hunk every
    # ``+``-prefixed line is an added line.
    in_hunk = False

    def flush() -> None:
        nonlocal added, current_file
        if not current_file or not added:
            added = []
            return
        kind = _kind_for_path(Path(current_file))
        # Build a sparse fragment: extract per contiguous added block so line
        # numbers stay accurate.
        block: list[str] = []
        block_start = 0
        prev_no = None
        for no, content in added:
            if prev_no is None or no == prev_no + 1:
                if not block:
                    block_start = no
                block.append(content)
            else:
                surfaces.extend(
                    extract_surfaces_from_text(
                        "\n".join(block),
                        current_file,
                        kind_for_whole_file=kind,
                        base_line=block_start,
                    )
                )
                block = [content]
                block_start = no
            prev_no = no
        if block:
            surfaces.extend(
                extract_surfaces_from_text(
                    "\n".join(block),
                    current_file,
                    kind_for_whole_file=kind,
                    base_line=block_start,
                )
            )
        added = []

    for line in diff_text.splitlines():
        # A "\ No newline at end of file" marker is diff METADATA, not a file
        # line — it must never advance the new-file counter (m11). Handle it
        # first so it can't fall through to the context-line branch, which would
        # drift every subsequent added line's reported number by +1.
        if line.startswith("\\ "):
            continue
        # File headers only outside a hunk (m10) — inside a hunk a ``+++ …`` line
        # is an added line whose content starts with ``++``, not a new-file header.
        if not in_hunk and line.startswith("+++ "):
            flush()
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            current_file = None if path == "/dev/null" else path
            continue
        if not in_hunk and line.startswith("--- "):
            continue
        if line.startswith("diff "):
            flush()
            current_file = None
            in_hunk = False
            continue
        m = _HUNK_RE.match(line)
        if m:
            new_lineno = int(m.group(1))
            in_hunk = True
            continue
        if in_hunk and line.startswith("+"):
            added.append((new_lineno, line[1:]))
            new_lineno += 1
        elif in_hunk and line.startswith("-"):
            continue
        elif in_hunk:
            # context line advances the new-file counter
            new_lineno += 1
    flush()
    return surfaces


def collect_diff(ref: str, *, repo: str | Path = ".") -> list[Surface]:
    """Run ``git diff <ref>`` in ``repo`` and collect Surfaces from added lines.

    Also includes commit messages introduced since ``ref`` as COMMIT_MSG
    surfaces (a documented injection vector). Fails soft: if ``git`` is missing
    or the ref is unknown, raises ``RuntimeError`` with a clear message.
    """
    repo = str(repo)
    try:
        # ``--no-color`` defeats a repo/user git config that sets
        # ``color.diff = always`` / ``color.ui = always``: without it git emits
        # ANSI escape codes even into the captured pipe, so every diff/header
        # line is prefixed with ``\x1b[...]`` and ``parse_unified_diff``'s
        # ``startswith("+++ ")`` / ``@@`` regex / ``startswith("+")`` checks
        # all fail — ``scan_diff`` silently returns zero findings
        # (fix-diff-color-config-breaks-scan).
        diff = subprocess.run(
            ["git", "-C", repo, "diff", "--unified=3", "--no-color", ref],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except FileNotFoundError as exc:  # git not installed
        raise RuntimeError("git is not installed or not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"git diff {ref} failed: {exc.stderr.strip() or exc}"
        ) from exc

    surfaces = parse_unified_diff(diff)
    surfaces.extend(_collect_commit_messages(ref, repo))
    return surfaces


def _collect_commit_messages(ref: str, repo: str) -> list[Surface]:
    """Collect commit messages on ``ref..HEAD`` as COMMIT_MSG surfaces."""
    try:
        out = subprocess.run(
            ["git", "-C", repo, "log", "--no-color",
             "--format=%H%x00%B%x00", f"{ref}..HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []
    surfaces: list[Surface] = []
    for chunk in out.split("\x00\n"):
        chunk = chunk.strip()
        if not chunk or "\x00" not in chunk:
            continue
        sha, body = chunk.split("\x00", 1)
        body = body.strip()
        if body:
            surfaces.append(
                Surface(body, f"commit:{sha[:8]}", 1, SurfaceKind.COMMIT_MSG)
            )
    return surfaces


# ---------------------------------------------------------------------------
# Mode 3: gh PR-files JSON
# ---------------------------------------------------------------------------


def parse_pr_files(files: list[dict]) -> list[Surface]:
    """Parse a list of ``gh api`` PR-file objects (``filename`` + ``patch``)."""
    surfaces: list[Surface] = []
    for entry in files:
        filename = entry.get("filename")
        patch = entry.get("patch")
        if not filename or not patch:
            continue
        # gh patches are headerless hunks; synthesize a +++ line so the unified
        # parser attributes them to the right file.
        synthetic = f"+++ b/{filename}\n{patch}"
        surfaces.extend(parse_unified_diff(synthetic))
    return surfaces


def collect_pr_json(path: str | Path) -> list[Surface]:
    """Load a ``gh api .../files`` JSON document and collect Surfaces.

    Accepts either a top-level JSON array of file objects or an object with a
    ``files`` key (both shapes ``gh`` can produce).
    """
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if isinstance(data, dict):
        files = data.get("files", [])
    else:
        files = data
    if not isinstance(files, list):
        raise ValueError(
            "PR JSON must be a list of file objects or have a 'files' key"
        )
    return parse_pr_files(files)
