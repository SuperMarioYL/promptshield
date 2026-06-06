# PromptShield demo — VHS tape (https://github.com/charmbracelet/vhs)
#
# Record with:  vhs assets/demo.tape
# It runs the scripted scan against the malicious-PR fixture and produces a GIF.
# To produce the asciinema cast that the README embeds, run the same commands
# under `asciinema rec` instead.
#
# Script:
#   1. scan ./tests/fixtures/malicious_pr  -> findings table, HIGH severity
#   2. scan --pr pr_files.json             -> exit 1 (CI fails)
#   3. the real Reddit data-nuking injection flagged on camera

Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0

Hide
Type "cd $(git rev-parse --show-toplevel)"  Enter
Type "clear"  Enter
Show

# --- 1. Scan the malicious PR fixture: a Rich findings table, all HIGH ---------
Type "# Your coding agent is about to read this repo. Scan it first."  Enter
Sleep 1500
Type "promptshield scan ./tests/fixtures/malicious_pr"  Enter
Sleep 4000

# --- 2. Same payload as a PR-files JSON: HIGH -> exit 1, CI goes red -----------
Type "# In CI, scan the PR JSON. A HIGH finding fails the check."  Enter
Sleep 1500
Type "promptshield scan --pr ./tests/fixtures/malicious_pr/pr_files.json; echo \"exit: $?\""  Enter
Sleep 4000

# --- 3. Point at the real Reddit data-nuking injection ------------------------
Type "# This is the real r/LocalLLaMA data-nuking injection — caught."  Enter
Sleep 1500
Type "grep -n 'rm -rf' ./tests/fixtures/malicious_pr/utils.py"  Enter
Sleep 3000

Type "# Caught before the agent ever read it."  Enter
Sleep 2500
