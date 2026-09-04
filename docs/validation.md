# Validation plan

## Hypothesis

Platform and application-security engineers lose time correlating a production
container finding with the repository and build that can fix it. Existing
scanners identify the vulnerable workload; Trace2Fix is useful only if the
handoff from that finding to an owned source change is still manual.

## Demo

Show one incident from beginning to end. Do not start with a product pitch.

1. A Trivy report identifies a vulnerable package in an image digest.
2. Kubernetes shows that exact digest running in one or more workloads.
3. SLSA provenance links the digest to a repository and commit.
4. Trace2Fix emits a reviewable remediation plan.

After the demo, ask the engineer to describe how the same incident is handled
in their environment today.

## Interview questions

1. Tell me about the last container vulnerability you had to remediate.
2. How did you find the repository, owning team and build for the deployed image?
3. Which parts were automated, and which required searching or asking people?
4. What evidence was needed before the finding could be closed?
5. Where would a generated remediation plan need to appear to fit the workflow?
6. Which wrong recommendation would make you stop trusting the tool?

Avoid asking whether the person "likes" the idea or would hypothetically use
it. Record concrete past behavior, time spent, tools used and failure modes.

## Decision gate

Continue to a Kubernetes/Trivy integration when, across at least eight
interviews:

- three engineers describe manual artifact-to-source correlation;
- two can provide a sanitized fixture or reproduce the workflow in a test repo;
- one agrees to run the prototype against a non-production cluster; and
- the problem is not already solved by configuring a tool they own.

Stop or narrow the project when fewer than three interviews show the problem,
or when the requested value is primarily another vulnerability dashboard.

## Evidence log

For each interview, record role, environment size, current workflow, time lost,
tools already deployed, trust requirements and the next concrete commitment.
Do not record company-sensitive vulnerability or infrastructure data.
