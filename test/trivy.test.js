import assert from 'node:assert/strict';
import test from 'node:test';
import { findingsFromTrivy } from '../src/trivy.js';

const hash = 'a'.repeat(64);

test('normalizes Trivy image vulnerabilities', () => {
  const report = {
    Metadata: { RepoDigests: [`ghcr.io/acme/orders@sha256:${hash}`] },
    Results: [
      {
        Target: 'alpine:3.20',
        Class: 'os-pkgs',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2026-0001',
            PkgName: 'openssl',
            InstalledVersion: '3.0.2',
            FixedVersion: '3.0.15-r0',
            Severity: 'HIGH',
            PrimaryURL: 'https://example.test/CVE-2026-0001',
          },
        ],
      },
    ],
  };

  assert.deepEqual(findingsFromTrivy(report), [
    {
      id: 'CVE-2026-0001',
      severity: 'high',
      image: { digest: `sha256:${hash}` },
      component: { name: 'openssl', type: 'os-pkg', version: '3.0.2' },
      fixedVersion: '3.0.15-r0',
      source: {
        scanner: 'trivy',
        target: 'alpine:3.20',
        primaryUrl: 'https://example.test/CVE-2026-0001',
      },
    },
  ]);
});

test('requires an immutable artifact identity', () => {
  assert.throws(
    () => findingsFromTrivy({ Metadata: {}, Results: [] }),
    /no immutable image digest/,
  );
});
