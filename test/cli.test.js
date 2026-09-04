import assert from 'node:assert/strict';
import test from 'node:test';
import { run } from '../src/cli.js';
import { readFile } from 'node:fs/promises';

const command = [
  'analyze',
  '--workload', 'examples/deployment.json',
  '--trivy', 'examples/trivy.json',
  '--provenance', 'examples/provenance.json',
  '--cve', 'CVE-2026-0001',
];

function captureOutput() {
  const stdout = [];
  const stderr = [];
  return {
    stdout,
    stderr,
    output: {
      log: (value) => stdout.push(value),
      error: (value) => stderr.push(value),
    },
  };
}

test('CLI prints a machine-readable report', async () => {
  const capture = captureOutput();
  const exitCode = await run(command, capture.output);

  assert.equal(exitCode, 0);
  assert.equal(capture.stderr.length, 0);
  const report = JSON.parse(capture.stdout[0]);
  assert.deepEqual(report.summary, { plans: 1, vulnerabilities: 1, workloads: 1 });
});

test('CLI rejects unknown options', async () => {
  await assert.rejects(
    () => run([...command, '--silently-ignore-this'], captureOutput().output),
    /Unknown option/,
  );
});

test('CLI accepts provenance verified by cosign', async () => {
  const capture = captureOutput();
  const digest = 'a'.repeat(64);
  let verificationOptions;
  const verifyAttestation = async (options) => {
    verificationOptions = options;
    return {
      statement: {
        subject: [{ digest: { sha256: digest } }],
        predicate: {
          buildDefinition: {
            buildType: 'https://slsa.dev/container-based-build/v0.1',
            resolvedDependencies: [
              {
                uri: 'git+https://github.com/acme/orders.git',
                digest: { gitCommit: '1a2b3c4d' },
              },
            ],
          },
        },
      },
      verification: { status: 'verified', verifier: 'cosign' },
    };
  };
  const args = [
    'analyze',
    '--workload', 'examples/deployment.json',
    '--trivy', 'examples/trivy.json',
    '--attestation-image', `ghcr.io/acme/orders@sha256:${digest}`,
    '--certificate-identity', 'https://github.com/acme/orders/.github/workflows/release.yml@refs/heads/main',
    '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
  ];

  const exitCode = await run(args, capture.output, { verifyAttestation });
  const report = JSON.parse(capture.stdout[0]);

  assert.equal(exitCode, 0);
  assert.equal(verificationOptions.image, `ghcr.io/acme/orders@sha256:${digest}`);
  assert.equal(report.plans[0].evidence.provenance.verification.status, 'verified');
});

test('inspect runs the read-only end-to-end workflow', async () => {
  const capture = captureOutput();
  const digest = 'a'.repeat(64);
  const fixture = async (name) => JSON.parse(
    await readFile(new URL(`../examples/${name}`, import.meta.url), 'utf8'),
  );
  const calls = [];
  const dependencies = {
    collectResources: async (options) => {
      calls.push(['collectResources', options]);
      const deployment = await fixture('deployment.json');
      deployment.kind = 'Pod';
      deployment.spec = deployment.spec.template.spec;
      return { kind: 'List', items: [deployment] };
    },
    scanImage: async (image) => {
      calls.push(['scanImage', image]);
      return fixture('trivy.json');
    },
    verifyAttestation: async (options) => {
      calls.push(['verifyAttestation', options]);
      return {
        statement: await fixture('provenance.json'),
        verification: { status: 'verified', verifier: 'cosign' },
      };
    },
  };
  const image = `ghcr.io/acme/orders@sha256:${digest}`;
  const exitCode = await run([
    'inspect',
    '--image', image,
    '--kube-context', 'staging',
    '--namespace', 'payments',
    '--certificate-identity', 'release-workflow',
    '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
  ], capture.output, dependencies);

  assert.equal(exitCode, 0);
  assert.deepEqual(calls[0], ['collectResources', { context: 'staging', namespace: 'payments' }]);
  assert.deepEqual(calls[1], ['scanImage', image]);
  assert.equal(calls[2][0], 'verifyAttestation');
  assert.equal(JSON.parse(capture.stdout[0]).summary.plans, 1);
});

test('inspect validates trust constraints before invoking tools', async () => {
  const calls = [];
  const dependencies = {
    collectResources: async () => calls.push('kubectl'),
    scanImage: async () => calls.push('trivy'),
    verifyAttestation: async () => calls.push('cosign'),
  };

  await assert.rejects(
    () => run([
      'inspect',
      '--image', `ghcr.io/acme/orders@sha256:${'a'.repeat(64)}`,
    ], captureOutput().output, dependencies),
    /requires exact certificate identity/,
  );
  assert.deepEqual(calls, []);
});
