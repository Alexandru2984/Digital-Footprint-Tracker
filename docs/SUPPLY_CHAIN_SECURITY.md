# Supply-chain security gates

The repository has a blocking, reproducible source-security gate. It runs on
every push and pull request, weekly against the complete history, and on manual
dispatch. A production deploy cannot start unless this gate succeeds.

## Enforced controls

| Control | Enforcement |
|---|---|
| Secret history | Gitleaks scans every reachable commit with 100% value redaction |
| Scanner integrity | Disposable positive and negative fixtures prove Gitleaks and Semgrep are not silent/no-op |
| SAST | Fifteen local Semgrep rules cover command/code injection, unsafe deserialization, TLS bypass, URL-to-DOM XSS, raw SQL, unsafe trust and shell bootstrap patterns |
| Changed dependencies | GitHub Dependency Review rejects newly introduced high-or-critical advisories on pull requests and exposes OpenSSF warnings |
| Existing dependencies | Pinned OSV-Scanner recursively audits the checked-out dependency manifests |
| Update discovery | Dependabot covers SwiftPM, both Python manifests, npm, GitHub Actions and Docker |
| SBOM | Pinned Syft emits SPDX 2.3 and CycloneDX JSON; validation requires Swift, npm and Python package URLs before upload |

The scanners run from immutable image digests, with no network during source
analysis. Semgrep uses only [the reviewed local rules](../.semgrep.yml), so a
mutable remote registry cannot change the build result. GitHub Actions are
pinned to full commit SHAs.

Current tool pins:

- Gitleaks 8.28.0:
  `sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854`
- Semgrep 1.172.0:
  `sha256:65dcd4408adda7c183a6b4550cb1e9b19f7f627a6fbb7e0559bd466bedc44d7b`
- Syft 1.51.0:
  `sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0`
- OSV-Scanner is pinned by digest in `.github/workflows/ci.yml`.

## Local verification

Docker, `jq`, Bash and ShellCheck are the only host requirements for these
commands:

```bash
scripts/run-security-gates.sh self-test
scripts/run-security-gates.sh scan
output_dir="$(mktemp -d)"
scripts/generate-sbom.sh "$output_dir"
```

The SBOM command mounts the checkout read-only, disables networking and writes
only the two requested JSON artifacts. The source version is the exact Git SHA.
The CI artifacts are retained for 14 days and named with that SHA.

## Historical finding baseline

The first full-history review found 37 `generic-api-key` introduction
fingerprints across 11 commits. Thirty corresponding secret-shaped literals
remain intentionally in the current test/example tree; none is an operational
credential, and the candidate history has zero unbaselined findings. Every
value was reviewed redacted and was one of:

- password/shared-secret literals used only by test fixtures;
- inert encryption-key examples in `.env.docker.example`;
- public VoidAccess commit and SHA-256 pins misclassified as API keys.

[`.gitleaksignore`](../.gitleaksignore) records only exact
`commit:path:rule:line` fingerprints. It does not allow a rule, path or regular
expression, so a new secret-like value in the same test or example file still
fails the build.

Do not add an exception merely to make CI green. First treat the value as
compromised, revoke/rotate it through its owner, determine every reachable
commit, and remove it from the current tree. Rewriting published history is a
separate destructive operation and requires explicit coordination. Only a
proven non-secret fixture may receive an exact fingerprint plus a review note.
Never paste a detected value into logs, issues, commit messages or this file.

## Remaining release controls

This gate inventories source dependencies and CI actions; it is not an SBOM of
the final Ubuntu runtime filesystem. The following remain required before the
repository can claim signed, reproducible delivery:

- build and scan the exact release container/host package closure;
- attach immutable SBOMs to a release rather than only a short-lived CI run;
- emit SLSA provenance, sign the artifact/image, and verify it on the VPS;
- pin apt repositories/package snapshots and enforce branch protection plus
  required checks in GitHub settings.

These gaps do not weaken the new source gate, but they keep the overall
production verdict blocked until the rollout acceptance evidence is complete.
