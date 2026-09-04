import assert from 'node:assert/strict';
import test from 'node:test';
import { run } from '../src/cli.js';

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
