# Security policy

## Supported versions

Trace2Fix is pre-1.0 software. Security fixes are made on `main` and released
from the latest minor version. Older minor versions are not maintained.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/qualv13/Trace2Fix/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Please include the affected version or commit, a minimal reproduction, the
security impact and any known mitigation. Reports are acknowledged on a
best-effort basis, with a target of seven days.

Issues worth reporting include verification bypasses, digest-confusion bugs,
command or argument injection, unsafe Kubernetes access and misleading trust
status in generated evidence.

The image under `test/e2e` is deliberately vulnerable so that Trivy has real
findings. Vulnerabilities inherited by that fixture are expected and are not
security defects in Trace2Fix. The fixture must not be used in production.
