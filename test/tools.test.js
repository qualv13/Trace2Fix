import assert from 'node:assert/strict';
import test from 'node:test';
import { collectPods, scanImage } from '../src/tools.js';

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

test('collects Pods from all namespaces by default', async () => {
  const recorded = recorder();
  const result = await collectPods({ context: 'staging' }, recorded.execute);

  assert.equal(result.kind, 'List');
  assert.deepEqual(recorded.calls[0].args, [
    'get', 'pods', '--context', 'staging', '--all-namespaces', '--output', 'json',
  ]);
});

test('limits Pod collection to an explicit namespace', async () => {
  const recorded = recorder();
  await collectPods({ namespace: 'payments' }, recorded.execute);
  assert.deepEqual(recorded.calls[0].args, [
    'get', 'pods', '--namespace', 'payments', '--output', 'json',
  ]);
});

test('scans only an immutable image reference', async () => {
  const recorded = recorder({ Results: [] });
  const image = `ghcr.io/acme/orders@${digest}`;
  await scanImage(image, recorded.execute);

  assert.equal(recorded.calls[0].file, 'trivy');
  assert.deepEqual(recorded.calls[0].args, [
    'image', '--quiet', '--format', 'json', '--scanners', 'vuln', '--', image,
  ]);
  assert.throws(() => scanImage('ghcr.io/acme/orders:latest'), /pinned by sha256/);
});

test('reports a missing external tool by name', async () => {
  const execute = async () => {
    const error = new Error('spawn kubectl ENOENT');
    error.code = 'ENOENT';
    throw error;
  };
  await assert.rejects(() => collectPods({}, execute), /requires kubectl on PATH/);
});
