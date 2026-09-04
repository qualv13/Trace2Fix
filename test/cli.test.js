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
    scanImage: async (options) => {
      calls.push(['scanImage', options]);
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
    '--timeout-seconds', '30',
    '--certificate-identity', 'release-workflow',
    '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
  ], capture.output, dependencies);

  assert.equal(exitCode, 0);
  assert.equal(calls[0][0], 'collectResources');
  assert.deepEqual(
    { ...calls[0][1], signal: undefined },
    { context: 'staging', namespace: 'payments', timeoutMs: 30_000, signal: undefined },
  );
  assert.ok(calls[0][1].signal instanceof AbortSignal);
  assert.equal(calls[1][0], 'scanImage');
  assert.equal(calls[1][1].image, image);
  assert.equal(calls[1][1].timeoutMs, 30_000);
  assert.equal(calls[1][1].signal, calls[0][1].signal);
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

test('inspect rejects an invalid timeout before invoking tools', async () => {
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
      '--certificate-identity', 'release-workflow',
      '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
      '--timeout-seconds', 'forever',
    ], captureOutput().output, dependencies),
    /must be an integer/,
  );
  assert.deepEqual(calls, []);
});

test('inspect cancels remaining work when one tool fails', async () => {
  const signals = [];
  const waitForCancellation = (options) => {
    signals.push(options.signal);
    return new Promise((resolve) => {
      options.signal.addEventListener('abort', () => resolve({}), { once: true });
    });
  };
  const dependencies = {
    collectResources: async (options) => {
      signals.push(options.signal);
      throw new Error('cluster unavailable');
    },
    scanImage: waitForCancellation,
    verifyAttestation: waitForCancellation,
  };

  await assert.rejects(
    () => run([
      'inspect',
      '--image', `ghcr.io/acme/orders@sha256:${'a'.repeat(64)}`,
      '--certificate-identity', 'release-workflow',
      '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
    ], captureOutput().output, dependencies),
    /cluster unavailable/,
  );
  assert.equal(signals.length, 3);
  assert.ok(signals.every((signal) => signal === signals[0]));
  assert.equal(signals[0].aborted, true);
});
