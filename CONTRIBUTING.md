# Contributing

Trace2Fix has a narrow purpose: connect a vulnerability in a deployed image to
the source and build that can remediate it. Before proposing a large feature,
open an issue describing a real remediation workflow and the evidence that is
currently assembled by hand.

## Development

Use Node.js 20 or newer and install the locked dependency tree:

```bash
npm ci
npm run check
npm test
npm run demo
```

Keep pull requests focused. Add tests for changed behavior and update the README
when the command-line interface changes. New runtime dependencies need a clear
reason; the current CLI has none.

Code that invokes external tools must preserve the existing trust boundaries:

- execute programs without a shell;
- require immutable image digests for live inspection;
- fail closed when provenance verification is unavailable or unsuccessful;
- keep unverified evidence visibly distinct from verified evidence; and
- keep Kubernetes access read-only.

Use short imperative commit subjects with the existing `feat:`, `fix:`,
`test:`, `docs:`, `ci:` or `chore:` prefixes.

Report suspected vulnerabilities through the process in
[`SECURITY.md`](SECURITY.md), not through a public issue.
