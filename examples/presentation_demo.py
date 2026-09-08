"""Scan fixtures as text, never execute them."""

import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for filename in ("clean.py", "utils.py"):
    result = subprocess.run(
        [
            str(root / ".venv/bin/promptshield"),
            "scan",
            "tests/fixtures/malicious_pr/" + filename,
            "--format",
            "json",
        ],
        cwd=root,
        text=True,
        capture_output=True,
    )
    report = json.loads(result.stdout)
    print(
        json.dumps(
            {
                "fixture": filename,
                "exit_code": result.returncode,
                "counts": report["counts"],
                "rule_ids": sorted({f["rule_id"] for f in report["findings"]}),
            }
        )
    )
    assert result.returncode == (0 if filename == "clean.py" else 1)
print("Scope: deterministic static fixture scan; no fixture code executed and no model called.")
