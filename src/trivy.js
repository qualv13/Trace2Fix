import { digestFromImageReference, normalizeDigest } from './input.js';

function artifactDigest(report) {
  const repoDigest = report?.Metadata?.RepoDigests?.find((value) =>
    digestFromImageReference(value),
  );
  const fromRepository = digestFromImageReference(repoDigest);
  if (fromRepository) return fromRepository;

  const imageId = report?.Metadata?.ImageID;
  if (imageId) return normalizeDigest(imageId, 'Trivy Metadata.ImageID');

  throw new Error(
    'Trivy report has no immutable image digest in Metadata.RepoDigests or Metadata.ImageID.',
  );
}

function componentType(result) {
  return result.Class === 'os-pkgs' ? 'os-pkg' : 'library';
}

/** Convert Trivy's report into the small finding model used by the planner. */
export function findingsFromTrivy(report) {
  if (!Array.isArray(report?.Results)) {
    throw new Error('Invalid Trivy report: Results must be an array.');
  }

  const digest = artifactDigest(report);
  const findings = [];
  for (const result of report.Results) {
    for (const vulnerability of result.Vulnerabilities ?? []) {
      if (!vulnerability.VulnerabilityID || !vulnerability.PkgName) continue;

      findings.push({
        id: vulnerability.VulnerabilityID,
        severity: String(vulnerability.Severity ?? 'UNKNOWN').toLowerCase(),
        image: { digest },
        component: {
          name: vulnerability.PkgName,
          type: componentType(result),
          version: vulnerability.InstalledVersion ?? null,
        },
        fixedVersion: vulnerability.FixedVersion || null,
        source: {
          scanner: 'trivy',
          target: result.Target ?? null,
          primaryUrl: vulnerability.PrimaryURL ?? null,
        },
      });
    }
  }
  return findings;
}
