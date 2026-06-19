# vhs tape — PromptShield happy path (https://github.com/charmbracelet/vhs)
# Rendered in CI by .github/workflows/demo.yml on every tag, or locally with:
#   vhs docs/demo.tape        (needs the `promptshield` CLI on PATH)
#
# Script:
#   1. scan the malicious-PR fixture -> Rich findings table, all HIGH
#   2. scan the same payload as a PR-files JSON -> exit 1 (CI goes red)
#   3. point at the real r/LocalLLaMA data-nuking injection -> caught
Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set Padding 18
Set TypingSpeed 45ms

# --- 1. Scan the malicious PR fixture: a Rich findings table, all HIGH ---------
Type "# Your coding agent is about to read this repo. Scan it first."
Enter
Sleep 1.5s
Type "promptshield scan ./tests/fixtures/malicious_pr"
Enter
Sleep 4s

# --- 2. Same payload as a PR-files JSON: HIGH -> exit 1, CI goes red -----------
Type "# In CI, scan the PR JSON. A HIGH finding fails the check."
Enter
Sleep 1.5s
Type "promptshield scan --pr ./tests/fixtures/malicious_pr/pr_files.json; echo \"exit: $?\""
Enter
Sleep 4s

# --- 3. Point at the real Reddit data-nuking injection ------------------------
Type "# This is the real r/LocalLLaMA data-nuking injection — caught."
Enter
Sleep 1.5s
Type "grep -n 'rm -rf' ./tests/fixtures/malicious_pr/utils.py"
Enter
Sleep 3s

Type "# Caught before the agent ever read it."
Enter
Sleep 2.5s
