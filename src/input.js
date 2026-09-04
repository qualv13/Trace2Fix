const SHA256 = /^sha256:[a-f0-9]{64}$/i;

export function normalizeDigest(value, fieldName = 'digest') {
  const digest = String(value ?? '').toLowerCase();
  if (!SHA256.test(digest)) {
    throw new Error(`${fieldName} must be a sha256 digest.`);
  }
  return digest;
}

export function digestFromImageReference(reference) {
  const separator = String(reference ?? '').lastIndexOf('@');
  if (separator === -1) return undefined;

  const digest = reference.slice(separator + 1).toLowerCase();
  return SHA256.test(digest) ? digest : undefined;
}

export function workloadItems(document) {
  if (document?.kind === 'List' || Array.isArray(document?.items)) {
    if (!Array.isArray(document.items)) {
      throw new Error('Kubernetes List.items must be an array.');
    }
    return document.items;
  }
  return [document];
}

export function podSpecFor(workload) {
  switch (workload?.kind) {
    case 'Pod':
      return workload.spec;
    case 'CronJob':
      return workload.spec?.jobTemplate?.spec?.template?.spec;
    default:
      return workload?.spec?.template?.spec;
  }
}

export function deployedContainers(workload) {
  const podSpec = podSpecFor(workload);
  if (!podSpec) return [];
  const specs = [...(podSpec.initContainers ?? []), ...(podSpec.containers ?? [])];
  if (workload?.kind !== 'Pod') return specs;

  const statuses = [
    ...(workload.status?.initContainerStatuses ?? []),
    ...(workload.status?.containerStatuses ?? []),
  ];
  return specs.map((container) => ({
    ...container,
    resolvedImage: statuses.find((status) => status.name === container.name)?.imageID,
  }));
}

export function matchingContainers(workload, digest) {
  return deployedContainers(workload).filter(
    (container) =>
      digestFromImageReference(container.resolvedImage) === digest ||
      digestFromImageReference(container.image) === digest,
  );
}
