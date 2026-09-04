import assert from 'node:assert/strict';
import test from 'node:test';
import { collectResources, scanImage } from '../src/tools.js';

const digest = `sha256:${'a'.repeat(64)}`;

function recorder(document = { kind: 'List', items: [] }) {
  const calls = [];
  return {
    calls,
    execute: async (file, args, options) => {
      calls.push({ file, args, options });
      return { stdout: JSON.stringify(document), stderr: '' };
    },
  };
}

test('collects runtime and owning resources from all namespaces by default', async () => {
  const recorded = recorder();
  const result = await collectResources(
    { context: 'staging', timeoutMs: 4_000 }, recorded.execute,
  );

  assert.equal(result.kind, 'List');
  assert.deepEqual(recorded.calls[0].args, [
    'get',
    'pods,replicasets.apps,deployments.apps,statefulsets.apps,daemonsets.apps,jobs.batch,cronjobs.batch',
    '--context', 'staging', '--all-namespaces', '--output', 'json',
  ]);
  assert.ok(recorded.calls[0].options.signal instanceof AbortSignal);
});

test('limits Pod collection to an explicit namespace', async () => {
  const recorded = recorder();
  await collectResources({ namespace: 'payments' }, recorded.execute);
  assert.deepEqual(recorded.calls[0].args, [
    'get',
    'pods,replicasets.apps,deployments.apps,statefulsets.apps,daemonsets.apps,jobs.batch,cronjobs.batch',
    '--namespace', 'payments', '--output', 'json',
  ]);
});

test('scans only an immutable image reference', async () => {
  const recorded = recorder({ Results: [] });
  const image = `ghcr.io/acme/orders@${digest}`;
  await scanImage({ image }, recorded.execute);

  assert.equal(recorded.calls[0].file, 'trivy');
  assert.deepEqual(recorded.calls[0].args, [
    'image', '--quiet', '--format', 'json', '--scanners', 'vuln', '--', image,
  ]);
  assert.throws(() => scanImage({ image: 'ghcr.io/acme/orders:latest' }), /pinned by sha256/);
});

test('reports a missing external tool by name', async () => {
  const execute = async () => {
    const error = new Error('spawn kubectl ENOENT');
    error.code = 'ENOENT';
    throw error;
  };
  await assert.rejects(() => collectResources({}, execute), /requires kubectl on PATH/);
});

test('distinguishes a command timeout from other failures', async () => {
  const execute = async () => {
    const error = new Error('aborted');
    error.name = 'AbortError';
    throw error;
  };
  await assert.rejects(
    () => collectResources({ timeoutMs: 2_000 }, execute),
    /timed out after 2 seconds/,
  );
});
