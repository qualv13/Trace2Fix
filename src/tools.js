import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { digestFromImageReference } from './input.js';

const execFile = promisify(execFileCallback);
const MAX_OUTPUT = 50 * 1024 * 1024;

async function executeJson(file, args, label, execute) {
  let result;
  try {
    result = await execute(file, args, { encoding: 'utf8', maxBuffer: MAX_OUTPUT });
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(`${label} requires ${file} on PATH.`);
    }
    const detail = error.stderr?.trim() || error.message;
    throw new Error(`${label} failed: ${detail}`);
  }

  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`${label} returned invalid JSON: ${error.message}`);
  }
}

export function collectResources(options = {}, execute = execFile) {
  const resourceTypes = [
    'pods',
    'replicasets.apps',
    'deployments.apps',
    'statefulsets.apps',
    'daemonsets.apps',
    'jobs.batch',
    'cronjobs.batch',
  ].join(',');
  const args = ['get', resourceTypes];
  if (options.context) args.push('--context', options.context);
  if (options.namespace) {
    args.push('--namespace', options.namespace);
  } else {
    args.push('--all-namespaces');
  }
  args.push('--output', 'json');
  return executeJson('kubectl', args, 'Kubernetes collection', execute);
}

export function scanImage(image, execute = execFile) {
  if (!digestFromImageReference(image)) {
    throw new Error('Live inspection requires an image pinned by sha256 digest.');
  }
  const args = ['image', '--quiet', '--format', 'json', '--scanners', 'vuln', '--', image];
  return executeJson('trivy', args, 'Trivy scan', execute);
}
