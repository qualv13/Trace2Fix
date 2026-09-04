import assert from 'node:assert/strict';
import test from 'node:test';
import { buildRemediationPlan, buildReport } from '../src/plan.js';

const digest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const workload = {
  apiVersion: 'apps/v1', kind: 'Deployment', metadata: { name: 'orders', namespace: 'production' },
  spec: { template: { spec: { containers: [{ name: 'api', image: `ghcr.io/acme/orders@${digest}` }] } } },
};
const finding = { id: 'CVE-2026-0001', severity: 'high', image: { digest }, component: { name: 'openssl', type: 'os-pkg', version: '3.0.2' }, fixedVersion: '3.0.15-r0' };
const provenance = { subject: [{ name: 'ghcr.io/acme/orders', digest: { sha256: digest.slice(7) } }], predicate: { buildDefinition: { buildType: 'https://slsa.dev/container-based-build/v0.1', resolvedDependencies: [{ uri: 'git+https://github.com/acme/orders.git', digest: { gitCommit: '1a2b3c4d' } }] } } };

test('ties a deployed vulnerable image to signed provenance and remediation', () => {
  const plan = buildRemediationPlan(workload, finding, provenance);
  assert.equal(plan.status, 'needs-review');
  assert.equal(plan.evidence.deployment.container, 'api');
  assert.equal(plan.evidence.provenance.sourceRepository, 'https://github.com/acme/orders');
  assert.deepEqual(plan.evidence.provenance.verification, { status: 'not-performed' });
  assert.equal(plan.recommendedChange.kind, 'rebuild-base-image');
});

test('rejects a provenance statement for another artifact', () => {
  const other = structuredClone(provenance);
  other.subject[0].digest.sha256 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  assert.throws(() => buildRemediationPlan(workload, finding, other), /does not match/);
});

test('builds plans for every matching workload', () => {
  const second = structuredClone(workload);
  second.metadata.name = 'orders-canary';
  const report = buildReport({ kind: 'List', items: [workload, second] }, [finding], provenance);

  assert.deepEqual(report.summary, { plans: 2, vulnerabilities: 1, workloads: 2 });
  assert.deepEqual(
    report.plans.map((plan) => plan.evidence.deployment.name),
    ['orders', 'orders-canary'],
  );
});

test('does not infer identity from mutable image tags', () => {
  const tagged = structuredClone(workload);
  tagged.spec.template.spec.containers[0].image = 'ghcr.io/acme/orders:latest';
  assert.throws(
    () => buildReport(tagged, [finding], provenance),
    /None of the findings refers/,
  );
});

test('uses the resolved image digest reported by a Pod', () => {
  const pod = {
    apiVersion: 'v1',
    kind: 'Pod',
    metadata: { name: 'orders-abc', namespace: 'production' },
    spec: { containers: [{ name: 'api', image: 'ghcr.io/acme/orders:main' }] },
    status: {
      containerStatuses: [
        {
          name: 'api',
          imageID: `docker-pullable://ghcr.io/acme/orders@${digest}`,
        },
      ],
    },
  };

  const report = buildReport(pod, [finding], provenance);
  assert.equal(report.plans[0].evidence.deployment.name, 'orders-abc');
  assert.equal(report.plans[0].evidence.deployment.image, 'ghcr.io/acme/orders:main');
});
