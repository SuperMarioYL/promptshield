# PromptShield demo — rendered to assets/demo.gif by vhs (.github/workflows/demo.yml)
Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1100
Set Height 660
Set Theme "Catppuccin Mocha"
Set Padding 20

Type "promptshield --version"
Enter
Sleep 1500ms

# The killer moment: the Reddit data-nuking injection fixture flags HIGH and
# fails the gate (exit 1).
Type "promptshield scan tests/fixtures/malicious_pr"
Enter
Sleep 3500ms

# Then the dogfood story: scanning PromptShield's own (noisy) repo is green
# because the committed .promptshield-baseline.yaml suppresses the ~100
# accepted self-findings — a new injection would still fail the gate.
Type "promptshield scan ."
Enter
Sleep 3500ms
