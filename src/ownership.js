function namespaceOf(resource) {
  return resource?.metadata?.namespace ?? 'default';
}

export function resourceReference(resource) {
  return {
    kind: resource?.kind,
    namespace: namespaceOf(resource),
    name: resource?.metadata?.name,
  };
}

function keyOf(reference) {
  return `${reference.namespace}\0${reference.kind}\0${reference.name}`;
}

function controllerReference(resource) {
  return resource?.metadata?.ownerReferences?.find((reference) => reference.controller === true);
}

export function resolveWorkloadOwner(resource, resources) {
  const index = new Map(resources.map((item) => [keyOf(resourceReference(item)), item]));
  const chain = [resourceReference(resource)];
  const visited = new Set([keyOf(chain[0])]);
  let current = resource;

  while (true) {
    const owner = controllerReference(current);
    if (!owner) {
      return { workload: current, chain, resolved: true };
    }

    const ownerReference = {
      kind: owner.kind,
      namespace: namespaceOf(current),
      name: owner.name,
    };
    const ownerKey = keyOf(ownerReference);
    if (visited.has(ownerKey)) {
      throw new Error(`Kubernetes ownership cycle detected at ${owner.kind}/${owner.name}.`);
    }

    const ownerResource = index.get(ownerKey);
    if (!ownerResource) {
      return { workload: current, chain, resolved: false, missingOwner: ownerReference };
    }

    chain.push(ownerReference);
    visited.add(ownerKey);
    current = ownerResource;
  }
}
