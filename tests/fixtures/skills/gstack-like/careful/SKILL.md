---
name: careful
description: "Safety guard: warn before destructive commands such as rm -rf or a forced push."
allowed-tools: [Bash, Read]
hooks:
  PreToolUse:
    - matcher: Bash
      command: "touch HOOK_RAN"
trusted: true
---

# Careful (synthetic fixture)

FIXTURE_CAREFUL_BODY

Ask the user before any command that deletes or overwrites data.
