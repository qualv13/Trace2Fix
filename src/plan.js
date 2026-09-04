import { matchingContainers, normalizeDigest, workloadItems } from './input.js';

function normalizeSubject(subject) {
  const digest = subject?.digest?.sha256;
  return digest ? `sha256:${digest}`.toLowerCase() : undefined;
}

function provenanceFields(provenance) {
  const statement = provenance?.statement ?? provenance;
  const verification = provenance?.statement
    ? provenance.verification
    : { status: 'not-performed' };
  const subjects = statement?.subject;
  if (!Array.isArray(subjects)) {
    throw new Error('Invalid provenance: subject must be an array.');
  }
  const subject = subjects.find((item) => normalizeSubject(item));
  const predicate = statement?.predicate ?? {};
  const buildDefinition = predicate.buildDefinition ?? predicate;
  const source = buildDefinition.resolvedDependencies?.find((dependency) =>
    dependency?.uri?.startsWith('git+') || dependency?.uri?.startsWith('https://github.com/'),
  )?.uri;
  const revision = buildDefinition.resolvedDependencies?.find((dependency) => dependency?.digest?.gitCommit)?.digest?.gitCommit;
  if (!source || !revision) {
    throw new Error('Provenance must identify a source repository and git commit.');
  }
  return {
    verification,
    digest: normalizeSubject(subject),
    sourceRepository: source?.replace(/^git\+/, '').replace(/\.git$/, ''),
    revision,
    buildType: buildDefinition.buildType,
  };
}

function remediationFor(finding) {
  const fixed = finding?.fixedVersion;
  if (finding?.component?.type === 'os-pkg') {
    return {
      kind: 'rebuild-base-image',
      instruction: fixed
        ? `Update the base image or OS package ${finding.component.name} to a release containing ${fixed}, then rebuild.`
        : `Update the base image or OS package ${finding.component?.name}, then rebuild and rescan.`,
    };
  }
  return {
    kind: 'update-application-dependency',
    instruction: fixed
      ? `Update ${finding.component?.name} to ${fixed} or later, rebuild, and redeploy.`
      : `Find an upstream fixed version for ${finding.component?.name}; rebuild and redeploy after updating it.`,
  };
}

/**
 * Creates an intentionally conservative plan: no ticket or pull request is
 * created. A later GitHub integration may use the returned evidence.
 */
export function buildRemediationPlan(workload, finding, provenance) {
  if (!finding?.id || !finding?.component?.name) {
    throw new Error('Finding must contain an id and component name.');
  }
  const findingDigest = normalizeDigest(finding?.image?.digest, 'Finding image digest');
  const container = matchingContainers(workload, findingDigest)[0];
  if (!container) {
    throw new Error(`Finding image digest ${findingDigest} is not deployed by this workload.`);
  }

  return planForContainer(workload, container, finding, provenanceFields(provenance));
}

function planForContainer(workload, container, finding, provenanceInfo) {
  const findingDigest = normalizeDigest(finding?.image?.digest, 'Finding image digest');
  if (provenanceInfo.digest !== findingDigest) {
    throw new Error('Provenance subject digest does not match the vulnerable deployed image.');
  }

  const remediation = remediationFor(finding);
  return {
    schemaVersion: 'trace2fix/v0alpha1',
    title: `${finding.id}: ${workload.kind}/${workload.metadata?.namespace ?? 'default'}/${workload.metadata?.name}`,
    status: 'needs-review',
    evidence: {
      vulnerability: {
        id: finding.id,
        severity: finding.severity,
        component: finding.component,
        fixedVersion: finding.fixedVersion ?? null,
        source: finding.source ?? null,
      },
      deployment: {
        kind: workload.kind,
        namespace: workload.metadata?.namespace ?? 'default',
        name: workload.metadata?.name,
        container: container.name,
        image: container.image,
        imageDigest: findingDigest,
      },
      provenance: provenanceInfo,
    },
    recommendedChange: remediation,
    verification: [
      'Build a new image and publish it under a new immutable digest.',
      'Generate an SBOM and vulnerability report for the new digest.',
      'Deploy the new digest and rerun trace2fix against the workload.',
    ],
    safety: 'This plan is evidence only; Trace2Fix does not create issues, pull requests, or change a cluster.',
  };
}

export function buildReport(workloadDocument, findings, provenance) {
  if (!Array.isArray(findings) || findings.length === 0) {
    throw new Error('No vulnerability findings to analyze.');
  }

  const workloads = workloadItems(workloadDocument);
  const provenanceInfo = provenanceFields(provenance);
  const plans = [];
  for (const finding of findings) {
    const digest = normalizeDigest(finding?.image?.digest, 'Finding image digest');
    for (const workload of workloads) {
      for (const container of matchingContainers(workload, digest)) {
        plans.push(planForContainer(workload, container, finding, provenanceInfo));
      }
    }
  }

  if (plans.length === 0) {
    throw new Error('None of the findings refers to an image pinned in the supplied workloads.');
  }

  return {
    schemaVersion: 'trace2fix/report/v0alpha1',
    summary: {
      plans: plans.length,
      vulnerabilities: new Set(plans.map((plan) => plan.evidence.vulnerability.id)).size,
      workloads: new Set(
        plans.map((plan) => {
          const target = plan.evidence.deployment;
          return `${target.kind}/${target.namespace}/${target.name}`;
        }),
      ).size,
    },
    plans,
  };
}
