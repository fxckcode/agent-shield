# Triage labels

Canonical five-role label vocabulary (GitHub labels):

| Label | Meaning |
|---|---|
| `needs-triage` | New issue, not yet classified |
| `needs-info` | Waiting on more information from the reporter |
| `ready-for-agent` | Triage done; safe for an agent to pick up |
| `ready-for-human` | Needs human review/decision |
| `wontfix` | Deliberately not fixing |

Apply with `gh issue edit <number> --add-label <label>`.