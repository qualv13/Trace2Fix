import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { parseArgs } from 'node:util';
import { buildReport } from './plan.js';
import { findingsFromTrivy } from './trivy.js';
import { verifyAttestation } from './cosign.js';
import { collectPods, scanImage } from './tools.js';
import { digestFromImageReference } from './input.js';

export function usage() {
  return `Usage:
  trace2fix analyze --workload <workload.json> (--trivy <report.json> | --finding <finding.json>) [provenance options] [--cve <id>]
  trace2fix inspect --image <image@sha256:digest> [--kube-context <name>] [--namespace <name>] --certificate-identity <identity> --certificate-oidc-issuer <issuer> [--cve <id>]

Provenance options:
  --provenance <statement.json>
  --attestation-image <image@digest> --certificate-identity <identity> --certificate-oidc-issuer <issuer>

The workload may be a single resource or a Kubernetes List. Output is JSON.`;
}

async function jsonFile(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(`Cannot read ${basename(path)}: ${error.message}`);
  }
}

export async function run(args, output = console, dependencies = {}) {
  const { positionals, values } = parseArgs({
    args,
    allowPositionals: true,
    strict: true,
    options: {
      workload: { type: 'string' },
      finding: { type: 'string' },
      trivy: { type: 'string' },
      provenance: { type: 'string' },
      'attestation-image': { type: 'string' },
      'certificate-identity': { type: 'string' },
      'certificate-oidc-issuer': { type: 'string' },
      image: { type: 'string' },
      'kube-context': { type: 'string' },
      namespace: { type: 'string' },
      cve: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  if (values.help) {
    output.log(usage());
    return 0;
  }
  if (positionals.length !== 1 || !['analyze', 'inspect'].includes(positionals[0])) {
    output.error(usage());
    return 2;
  }

  const command = positionals[0];
  const report = command === 'inspect'
    ? await runInspection(values, dependencies)
    : await runAnalysis(values, dependencies);
  output.log(JSON.stringify(report, null, 2));
  return 0;
}

function filterFindings(findings, cve) {
  const selected = cve ? findings.filter((finding) => finding.id === cve) : findings;
  if (selected.length === 0) {
    throw new Error(cve ? `Vulnerability ${cve} was not found.` : 'No vulnerabilities were found.');
  }
  return selected;
}

async function runAnalysis(values, dependencies) {
  const { workload: workloadPath, finding: findingPath } = values;
  const trivyPath = values.trivy;
  const provenancePath = values.provenance;
  const attestationImage = values['attestation-image'];
  if (
    !workloadPath ||
    values.image ||
    values['kube-context'] ||
    values.namespace ||
    Boolean(findingPath) === Boolean(trivyPath) ||
    Boolean(provenancePath) === Boolean(attestationImage)
  ) {
    throw new Error(`Expected one finding source and all required inputs.\n\n${usage()}`);
  }

  const findings = filterFindings(findingPath
    ? [await jsonFile(findingPath)]
    : findingsFromTrivy(await jsonFile(trivyPath)), values.cve);

  const provenance = provenancePath
    ? await jsonFile(provenancePath)
    : await (dependencies.verifyAttestation ?? verifyAttestation)({
      image: attestationImage,
      certificateIdentity: values['certificate-identity'],
      certificateOidcIssuer: values['certificate-oidc-issuer'],
    });

  return buildReport(
    await jsonFile(workloadPath),
    findings,
    provenance,
  );
}

async function runInspection(values, dependencies) {
  const image = values.image;
  if (
    !image ||
    values.workload ||
    values.trivy ||
    values.finding ||
    values.provenance ||
    values['attestation-image']
  ) {
    throw new Error(`Live inspection accepts --image instead of file inputs.\n\n${usage()}`);
  }
  if (!digestFromImageReference(image)) {
    throw new Error('Live inspection requires an image pinned by sha256 digest.');
  }
  if (!values['certificate-identity'] || !values['certificate-oidc-issuer']) {
    throw new Error('Live inspection requires exact certificate identity and OIDC issuer.');
  }

  const [workloads, trivyReport, provenance] = await Promise.all([
    (dependencies.collectPods ?? collectPods)({
      context: values['kube-context'],
      namespace: values.namespace,
    }),
    (dependencies.scanImage ?? scanImage)(image),
    (dependencies.verifyAttestation ?? verifyAttestation)({
      image,
      certificateIdentity: values['certificate-identity'],
      certificateOidcIssuer: values['certificate-oidc-issuer'],
    }),
  ]);
  const findings = filterFindings(findingsFromTrivy(trivyReport), values.cve);
  return buildReport(workloads, findings, provenance);
}
