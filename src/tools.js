import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { digestFromImageReference } from './input.js';

const execFile = promisify(execFileCallback);
const MAX_OUTPUT = 50 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

function commandSignal(timeoutMs, signal) {
  const timeout = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

async function executeJson(file, args, label, timeoutMs, signal, execute) {
  let result;
  try {
    result = await execute(file, args, {
      encoding: 'utf8',
      maxBuffer: MAX_OUTPUT,
      signal: commandSignal(timeoutMs, signal),
    });
  } catch (error) {
    if (error.name === 'AbortError' || error.code === 'ABORT_ERR') {
      if (signal?.aborted) throw new Error(`${label} cancelled.`);
      throw new Error(`${label} timed out after ${Math.ceil(timeoutMs / 1000)} seconds.`);
    }
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
  return executeJson(
    'kubectl',
    args,
    'Kubernetes collection',
    options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    options.signal,
    execute,
  );
}

export function scanImage(options, execute = execFile) {
  const { image, timeoutMs = DEFAULT_TIMEOUT_MS, signal } = options;
  if (!digestFromImageReference(image)) {
    throw new Error('Live inspection requires an image pinned by sha256 digest.');
  }
  const args = ['image', '--quiet', '--format', 'json', '--scanners', 'vuln', '--', image];
  return executeJson('trivy', args, 'Trivy scan', timeoutMs, signal, execute);
}
