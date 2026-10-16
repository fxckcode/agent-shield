#!/usr/bin/env python3
"""Acceptance checklist: runs each security property's test target and reports pass/fail.

Usage:
    python3 probes/checklist.py

Requires a Rust toolchain on PATH (or run it inside the same container CI uses).
"""
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
checks = []


def run(args, cwd=REPO):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=300)
    return r.returncode, (r.stdout + r.stderr)


def test_target(label, target, filt=None):
    args = ["cargo", "test", "--test", target]
    if filt:
        args.append(filt)
    rc, out = run(args)
    passed = rc == 0 and "test result: ok" in out
    evidence = out.splitlines()[-2] if passed and len(out.splitlines()) >= 2 else out[-200:]
    checks.append((label, passed, evidence))


# 1. SSRF: private / loopback / link-local / metadata / unspecified are blocked.
test_target("1: SSRF destinations blocked", "ssrf_block")

# 2. Redirects are revalidated per hop and cannot escape the policy.
test_target("2: redirects revalidated per hop", "redirect_policy")

# 3. Dangerous content types, oversized bodies, excessive redirects blocked.
test_target("3: content-type / size / redirect limits enforced", "content_envelope")

# 4. External content is wrapped in an untrusted-data envelope.
test_target("4: untrusted-data envelope applied", "content_envelope", "envelope")

# 5. Prompt injection is detected or quarantined; uncertain classifications fail closed.
test_target("5: prompt injection fails closed", "injection_detection")

# 6. Blocks report a reason code and correlation id without echoing secrets.
rc, out = run(["cargo", "test", "error_display"])
checks.append(
    (
        "6: blocks carry reason code + correlation id",
        rc == 0,
        "error display tests OK" if rc == 0 else out[-200:],
    )
)

ok = all(c[1] for c in checks)
for name, passed, evidence in checks:
    print(("PASS" if passed else "FAIL"), "|", name, "|", evidence)
print("RESULT:", "ALL CRITERIA OK" if ok else "CRITERIA MISSING")
sys.exit(0 if ok else 1)
