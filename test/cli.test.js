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
