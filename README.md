# Trace2Fix

[![CI](https://github.com/qualv13/Trace2Fix/actions/workflows/ci.yml/badge.svg)](https://github.com/qualv13/Trace2Fix/actions/workflows/ci.yml)
[![Trusted E2E](https://github.com/qualv13/Trace2Fix/actions/workflows/trusted-e2e.yml/badge.svg)](https://github.com/qualv13/Trace2Fix/actions/workflows/trusted-e2e.yml)

Trace2Fix is a deliberately small proof of concept for one question that
container scanners do not answer end-to-end:

> A vulnerable package is running in this Kubernetes workload. Where should we
> change the source, and how do we prove the replacement is deployed?

It receives Kubernetes workloads, a Trivy report, and an in-toto/SLSA
provenance statement. It accepts the result only when the image digest agrees
in all three places, then emits reviewable remediation plans.

## Why this is not another scanner

Trivy and Kubescape already scan images and clusters well. Trace2Fix consumes
their evidence or invokes the existing Trivy CLI; it does not implement a
scanner, operate a controller, or create PRs. The experiment is whether the
**evidence-to-remediation** hand-off is painful enough for platform and AppSec
teams to adopt a focused tool.

## Run the demo

Requires Node.js 20+.

```bash
npm ci
npm run check
npm test
npm run demo
```

The command produces a JSON report with the vulnerable component, the exact
workload and immutable digest, the source repository and revision from
provenance, a remediation suggestion, and verification steps.

To analyze a real Trivy JSON report exported for an image:

```bash
trace2fix analyze \
  --workload deployments.json \
  --trivy trivy.json \
  --provenance provenance.json \
  --cve CVE-2026-0001
```

For trusted provenance, let Trace2Fix invoke cosign with an exact certificate
identity:

```bash
trace2fix analyze \
  --workload pods.json \
  --trivy trivy.json \
  --attestation-image ghcr.io/acme/orders@sha256:... \
  --certificate-identity https://github.com/acme/orders/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

This mode requires `cosign` on `PATH`. Trace2Fix uses `execFile`, passes each
argument separately, requires SLSA provenance v1, and records the certificate
constraints in the report.

To collect the evidence without preparing intermediate files, use `inspect`:

```bash
trace2fix inspect \
  --image ghcr.io/acme/orders@sha256:... \
  --kube-context staging \
  --namespace payments \
  --timeout-seconds 300 \
  --certificate-identity https://github.com/acme/orders/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

This path requires `kubectl`, `trivy`, and `cosign` on `PATH`. It reads Pods and
their standard workload controllers, scans the specified image and verifies
its attestation concurrently. The image must be pinned by digest. Omitting
`--namespace` reads resources from all namespaces visible to the current
Kubernetes identity.

For local evaluation or an air-gapped environment, `inspect` can read an
existing provenance statement instead of invoking cosign:

```bash
trace2fix inspect \
  --image ghcr.io/acme/orders@sha256:... \
  --namespace payments \
  --provenance provenance.json
```

This mode still invokes `kubectl` and `trivy`, but marks provenance verification
as `not-performed`. It is suitable for testing the correlation workflow, not
for producing trusted security evidence.

## Trusted end-to-end check

The manually triggered
[`Trusted end-to-end`](https://github.com/qualv13/Trace2Fix/actions/workflows/trusted-e2e.yml)
workflow exercises the trusted path against real tools. It builds and publishes
an immutable [GHCR test image](https://github.com/qualv13/Trace2Fix/pkgs/container/trace2fix-e2e),
creates a keyless SLSA provenance v1 attestation with GitHub OIDC, deploys the
image to a temporary Kind cluster, scans it with Trivy and runs
`trace2fix inspect`. The check fails unless at least one remediation plan is
produced and every plan contains the deployed digest and
`verification.status: verified`.

The fixture intentionally uses an old base image so that the scan has real
findings. It is labeled as non-production and should never be used as an
application base image. Actions and tool versions in the workflow are pinned;
upgrades are reviewed explicitly.

External commands have a five-minute timeout by default. Use
`--timeout-seconds` to select a value from 1 to 1800 seconds. If one command
fails, Trace2Fix cancels the remaining collection work.

For images referenced by a mutable tag, Trace2Fix takes the immutable digest
from Pod status and follows Kubernetes `ownerReferences`, for example `Pod →
ReplicaSet → Deployment`. Multiple replicas of the same workload produce one
plan with every observed Pod recorded as evidence. Missing owners are reported
as unresolved; names are never used to guess ownership.

## Inputs

`--workload` accepts a single Kubernetes workload or a `List` returned by
`kubectl get ... -o json`. For controllers, container images must be pinned by
digest. For Pods, Trace2Fix can use the immutable `imageID` reported in
`status.containerStatuses`, so a practical input is `kubectl get pods -A -o
json` even when the manifest uses tags.
`--trivy` accepts the JSON produced by `trivy image --format json`. For fixture
and integration testing, `--finding` accepts the normalized internal format.
`--provenance` accepts an in-toto Statement containing an SLSA provenance
predicate. The subject's SHA-256 must equal both the finding and the deployed
container image digest.

## Safety and boundaries

- `inspect` only runs `kubectl get` for Pods, ReplicaSets, Deployments,
  StatefulSets, DaemonSets, Jobs and CronJobs; it does not create, patch or
  delete Kubernetes resources.
- External commands are executed directly without a shell. User values are
  passed as individual arguments.
- A raw `--provenance` file is useful for local fixtures but is marked
  `not-performed`. Use the cosign options above when the report will be treated
  as security evidence.
- No automatic ticket or PR creation. The plan is `needs-review` by design.

## Validation gate

We proceed beyond this prototype only if interviews show that at least three
platform/AppSec engineers manually correlate deployment, digest, provenance,
repository and ownership during vulnerability remediation. We will not add
automatic GitHub issues or remediation pull requests before that validation.

The interview script and explicit stop conditions are in
[`docs/validation.md`](docs/validation.md).

## License

MIT
