import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);
const SLSA_PROVENANCE_V1 = 'https://slsa.dev/provenance/v1';

function parseJsonDocuments(output) {
  const trimmed = output.trim();
  if (!trimmed) throw new Error('Cosign returned no attestations.');

  try {
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return trimmed.split('\n').filter(Boolean).map((line) => JSON.parse(line));
  }
}

function decodeStatement(envelope) {
  if (envelope?.payloadType !== 'application/vnd.in-toto+json' || !envelope?.payload) {
    return undefined;
  }

  try {
    return JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8'));
  } catch (error) {
    throw new Error(`Cosign returned an invalid in-toto payload: ${error.message}`);
  }
}

export function statementFromCosignOutput(output) {
  const statements = parseJsonDocuments(output).map(decodeStatement).filter(Boolean);
  const provenance = statements.find(
    (statement) => statement.predicateType === SLSA_PROVENANCE_V1,
  );
  if (!provenance) {
    throw new Error('Cosign returned no SLSA provenance v1 attestation.');
  }
  return provenance;
}

export async function verifyAttestation(options, execute = execFile) {
  const { image, certificateIdentity, certificateOidcIssuer } = options;
  if (!image || !certificateIdentity || !certificateOidcIssuer) {
    throw new Error('Cosign verification requires an image, certificate identity and OIDC issuer.');
  }

  const args = [
    'verify-attestation',
    '--type', 'slsaprovenance1',
    '--certificate-identity', certificateIdentity,
    '--certificate-oidc-issuer', certificateOidcIssuer,
    '--output', 'json',
    '--',
    image,
  ];
  let result;
  try {
    result = await execute('cosign', args, { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 });
  } catch (error) {
    const detail = error.stderr?.trim() || error.message;
    throw new Error(`Cosign verification failed: ${detail}`);
  }

  return {
    statement: statementFromCosignOutput(result.stdout),
    verification: {
      status: 'verified',
      verifier: 'cosign',
      certificateIdentity,
      certificateOidcIssuer,
    },
  };
}
