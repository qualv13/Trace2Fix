import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { parseArgs } from 'node:util';
import { buildReport } from './plan.js';
import { findingsFromTrivy } from './trivy.js';

export function usage() {
  return `Usage:
  trace2fix analyze --workload <workload.json> (--trivy <report.json> | --finding <finding.json>) --provenance <statement.json> [--cve <id>]

The workload may be a single resource or a Kubernetes List. Output is JSON.`;
}

async function jsonFile(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(`Cannot read ${basename(path)}: ${error.message}`);
  }
}

export async function run(args, output = console) {
  const { positionals, values } = parseArgs({
    args,
    allowPositionals: true,
    strict: true,
    options: {
      workload: { type: 'string' },
      finding: { type: 'string' },
      trivy: { type: 'string' },
      provenance: { type: 'string' },
      cve: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  if (values.help) {
    output.log(usage());
    return 0;
  }
  if (positionals.length !== 1 || positionals[0] !== 'analyze') {
    output.error(usage());
    return 2;
  }

  const { workload: workloadPath, finding: findingPath } = values;
  const { trivy: trivyPath, provenance: provenancePath } = values;
  if (!workloadPath || !provenancePath || Boolean(findingPath) === Boolean(trivyPath)) {
    throw new Error(`Expected one finding source and all required inputs.\n\n${usage()}`);
  }

  let findings = findingPath
    ? [await jsonFile(findingPath)]
    : findingsFromTrivy(await jsonFile(trivyPath));
  if (values.cve) {
    findings = findings.filter((finding) => finding.id === values.cve);
  }
  if (findings.length === 0) {
    throw new Error(
      values.cve ? `Vulnerability ${values.cve} was not found.` : 'No vulnerabilities were found.',
    );
  }

  const report = buildReport(
    await jsonFile(workloadPath),
    findings,
    await jsonFile(provenancePath),
  );
  output.log(JSON.stringify(report, null, 2));
  return 0;
}
