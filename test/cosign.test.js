import assert from 'node:assert/strict';
import test from 'node:test';
import { statementFromCosignOutput, verifyAttestation } from '../src/cosign.js';

const statement = {
  _type: 'https://in-toto.io/Statement/v1',
  predicateType: 'https://slsa.dev/provenance/v1',
  subject: [{ name: 'ghcr.io/acme/orders', digest: { sha256: 'a'.repeat(64) } }],
  predicate: {},
};

function envelope(value = statement) {
  return {
    payloadType: 'application/vnd.in-toto+json',
    payload: Buffer.from(JSON.stringify(value)).toString('base64'),
    signatures: [{ sig: 'fixture' }],
  };
}

test('extracts SLSA provenance from cosign output', () => {
  const output = JSON.stringify([envelope()]);
  assert.deepEqual(statementFromCosignOutput(output), statement);
});

test('uses exact certificate constraints when invoking cosign', async () => {
  let invocation;
  const execute = async (file, args, options) => {
    invocation = { file, args, options };
    return { stdout: JSON.stringify(envelope()), stderr: '' };
  };

  const result = await verifyAttestation({
    image: `ghcr.io/acme/orders@sha256:${'a'.repeat(64)}`,
    certificateIdentity: 'https://github.com/acme/orders/.github/workflows/release.yml@refs/heads/main',
    certificateOidcIssuer: 'https://token.actions.githubusercontent.com',
  }, execute);

  assert.equal(invocation.file, 'cosign');
  assert.deepEqual(invocation.args.slice(0, 7), [
    'verify-attestation',
    '--type', 'slsaprovenance1',
    '--certificate-identity',
    'https://github.com/acme/orders/.github/workflows/release.yml@refs/heads/main',
    '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
  ]);
  assert.equal(invocation.args.at(-2), '--');
  assert.equal(invocation.args.at(-1), `ghcr.io/acme/orders@sha256:${'a'.repeat(64)}`);
  assert.ok(invocation.options.signal instanceof AbortSignal);
  assert.equal(result.verification.status, 'verified');
});

test('reports cosign timeouts separately', async () => {
  const execute = async () => {
    const error = new Error('aborted');
    error.code = 'ABORT_ERR';
    throw error;
  };
  await assert.rejects(
    () => verifyAttestation({
      image: `ghcr.io/acme/orders@sha256:${'a'.repeat(64)}`,
      certificateIdentity: 'release-workflow',
      certificateOidcIssuer: 'https://token.actions.githubusercontent.com',
      timeoutMs: 3_000,
    }, execute),
    /timed out after 3 seconds/,
  );
});

test('rejects output without SLSA provenance v1', () => {
  const other = { ...statement, predicateType: 'https://spdx.dev/Document' };
  assert.throws(
    () => statementFromCosignOutput(JSON.stringify(envelope(other))),
    /no SLSA provenance v1/,
  );
});
