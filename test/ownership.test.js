import assert from 'node:assert/strict';
import test from 'node:test';
import { resolveWorkloadOwner } from '../src/ownership.js';

function resource(kind, name, owner) {
  return {
    kind,
    metadata: {
      name,
      namespace: 'production',
      ...(owner ? { ownerReferences: [{ ...owner, controller: true }] } : {}),
    },
  };
}

test('follows Kubernetes controller ownership without name inference', () => {
  const pod = resource('Pod', 'orders-7bd9d6f8b4-abcde', {
    kind: 'ReplicaSet', name: 'orders-7bd9d6f8b4',
  });
  const replicaSet = resource('ReplicaSet', 'orders-7bd9d6f8b4', {
    kind: 'Deployment', name: 'orders',
  });
  const deployment = resource('Deployment', 'orders');

  const result = resolveWorkloadOwner(pod, [deployment, pod, replicaSet]);

  assert.equal(result.workload, deployment);
  assert.equal(result.resolved, true);
  assert.deepEqual(result.chain.map(({ kind, name }) => `${kind}/${name}`), [
    'Pod/orders-7bd9d6f8b4-abcde',
    'ReplicaSet/orders-7bd9d6f8b4',
    'Deployment/orders',
  ]);
});

test('reports an owner missing from the collected resources', () => {
  const pod = resource('Pod', 'orders-abcde', {
    kind: 'ReplicaSet', name: 'orders-7bd9d6f8b4',
  });

  const result = resolveWorkloadOwner(pod, [pod]);

  assert.equal(result.workload, pod);
  assert.equal(result.resolved, false);
  assert.deepEqual(result.missingOwner, {
    kind: 'ReplicaSet', namespace: 'production', name: 'orders-7bd9d6f8b4',
  });
});

test('rejects ownership cycles in malformed input', () => {
  const first = resource('Pod', 'first', { kind: 'Pod', name: 'second' });
  const second = resource('Pod', 'second', { kind: 'Pod', name: 'first' });

  assert.throws(
    () => resolveWorkloadOwner(first, [first, second]),
    /ownership cycle/,
  );
});
