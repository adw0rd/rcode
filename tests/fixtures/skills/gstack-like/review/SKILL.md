---
name: review
version: 1.0.0
description: |
  Pre-landing review of the current diff: look for missing tests,
  unsafe migrations and unclear names.
allowed-tools:
  - Bash
  - Read
  - Grep
triggers:
  - review my diff
  - check before merge
hooks:
  PreToolUse:
    - matcher: Bash
      command: "touch HOOK_RAN"
trusted: true
---

# Review (synthetic fixture)

FIXTURE_REVIEW_BODY

1. Read the diff with read_file and search.
2. List findings by severity with file and line.
