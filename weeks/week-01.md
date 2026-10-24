# Week 01 · A public repo that refuses secrets

Sprint 1 · 19–25 Oct 2026 · Matching TEK-UP course: none yet (Réseaux IP-1 comes next)

## Goal

Set up a public lab notebook where I can't commit a password, key or token by accident.

## What I learned (3 sentences, notes closed)

1. Git saves my project as a series of snapshots (commits), and the staging area decides what goes into the next snapshot.
2. Deleting a secret in a new commit doesn't remove it, because Git preserves previous snapshots in the history; if a key was pushed, I rotate it first, then clean the history with git-filter-repo.
3. I keep secrets out of my commits by using a `.gitignore` for files like `.env`, a gitleaks pre-commit hook that blocks secrets, and GitHub push protection as a last check.

## What I built

A Git repo with a pre-commit hook that runs gitleaks on every commit and blocks it if it finds a secret.

```powershell
# Tools
winget install Gitleaks.Gitleaks
pip install pre-commit

# Repo and hook
git init
pre-commit install
git add .gitignore .pre-commit-config.yaml README.md templates/week-template.md
git commit -m "Set up lab notebook with gitleaks pre-commit scan"

# Publish
git remote add origin https://github.com/souchaine/soc-lab-notebook.git
git push -u origin main
```

The hook config:

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks-system
        pass_filenames: false
```

`pass_filenames: false` matters: `gitleaks git` accepts at most one argument, so letting pre-commit pass the list of staged files would break the hook.

Test: I staged a file holding a fake GitHub token. gitleaks blocked the commit with rule `github-pat`. A clean commit went through.

## What broke and how I fixed it

My first push was rejected with "fetch first". I had created the GitHub repo with an automatic README, so GitHub had a commit my local repo didn't have.

```powershell
git fetch origin
git log origin/main --oneline        # only the auto README, nothing to keep
git push -u origin main --force-with-lease
```

`--force-with-lease` overwrites the remote only if it still matches what I just fetched. A plain `--force` would overwrite anything, including work pushed by someone else in the meantime.

## Proof

- The hook is live in this repo: see [`.pre-commit-config.yaml`](../.pre-commit-config.yaml), added in commit `e3c5f22`.
- The test: gitleaks stopped the commit holding the fake token and reported rule `github-pat`. The clean commit went through.
- The page you're reading passed the same hook before it was committed.

## Next

After my exams (from 9 Nov): how a network works, OSI and TCP/IP, and a map of my lab's VM network.

## Privacy check (before every commit and post)

- [x] No real IP addresses, hostnames or usernames
- [x] No passwords, keys or tokens
- [x] No school or employer data
- [x] Screenshots cropped to what matters
- [x] gitleaks passed on commit
