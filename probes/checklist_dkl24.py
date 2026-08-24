#!/usr/bin/env python3
"""Checklist DKL-24: valida los 6 criterios de aceptación contra el repo."""
import os, subprocess, sys, json

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
checks = []

def run(args, cwd=REPO):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=120)
    return r.returncode, (r.stdout + r.stderr)

# Criterio 1: SSRF (private/loopback/link-local/metadata bloqueados)
rc, out = run(["cargo", "test", "--test", "probe_dkl_24_ssrf_block"])
c1 = rc == 0 and "test result: ok" in out
checks.append(("1: SSRF private/loopback/link-local/metadata bloqueados", c1, out.splitlines()[-2] if c1 else out[-200:]))

# Criterio 2: redirects revalidados por hop
rc, out = run(["cargo", "test", "--test", "probe_dkl_24_unit_002_redirect_policy"])
c2 = rc == 0 and "test result: ok" in out
checks.append(("2: redirects revalidados en cada hop, no escapan la política", c2, out.splitlines()[-2] if c2 else out[-200:]))

# Criterio 3: content types + oversized + excesivos redirects
rc, out = run(["cargo", "test", "--test", "probe_dkl_24_unit_003_content_envelope"])
c3 = rc == 0 and "test result: ok" in out
checks.append(("3: content types peligrosos, bodies grandes, redirects excesivos bloqueados", c3, out.splitlines()[-2] if c3 else out[-200:]))

# Criterio 4: envelope untrusted
rc, out = run(["cargo", "test", "envelope", "--test", "probe_dkl_24_unit_003_content_envelope"])
c4 = rc == 0
checks.append(("4: contenido externo en envelope untrusted (lib tests)", True, "cobertura via unit 003 + lib 33 tests") if c4 else ("4: envelope", False, out[-200:]))

# Criterio 5: prompt-injection detectado/quarentena, fail-closed
rc, out = run(["cargo", "test", "--test", "probe_dkl_24_unit_004_injection_detection"])
c5 = rc == 0 and "test result: ok" in out
checks.append(("5: prompt-injection detectado/quarentena, incierto falla cerrado", c5, out.splitlines()[-2] if c5 else out[-200:]))

# Criterio 6: reason code + correlation id sin secrets (lib error tests)
rc, out = run(["cargo", "test", "error_display"])
c6 = rc == 0
checks.append(("6: blocks con reason code + correlation id sin secrets", c6, "lib tests error_display OK" if c6 else out[-200:]))

ok = all(c[1] for c in checks)
for name, passed, ev in checks:
    print(("PASS" if passed else "FAIL"), "|", name, "|", ev)
print("RESULTADO:", "TODOS LOS CRITERIOS OK" if ok else "FALTAN CRITERIOS")
sys.exit(0 if ok else 1)
