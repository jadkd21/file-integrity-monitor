# File Integrity Monitor (FIM)

A Python tool that fingerprints every file in a folder with SHA-256 hashes,
then re-checks later and reports exactly what changed: new, deleted, or
modified files.

## How to run

```
python fim.py init    - fingerprint a folder (creates the baseline)
python fim.py check   - detect changes since the baseline
```

Press Enter at the folder prompt to monitor the current folder.

## Try it

1. `python fim.py init` — baseline your folder
2. Edit, add, or delete a file in that folder
3. `python fim.py check` — watch it catch every change

## What I learned

- SHA-256 hashing: one changed byte = completely different fingerprint
- How real integrity tools (Tripwire, Wazuh FIM) detect intrusions
- Attackers modify system files to persist — a FIM is how defenders notice
- Baseline comparison: new vs deleted vs modified

## Note

A FIM only detects change, it doesn't judge it — Windows updates modify
files legitimately all the time. The skill is investigating the unexpected.
