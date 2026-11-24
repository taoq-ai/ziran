# Security policy

## Supported versions

ziran is in the 0.x series. Security fixes land in the latest minor release only; upgrade to
it to get them.

| Version | Supported |
|---|---|
| Latest 0.x minor release | Yes |
| Earlier releases | No |

## Reporting a vulnerability

Report a vulnerability in ziran itself privately through GitHub:
[Report a vulnerability](https://github.com/taoq-ai/ziran/security/advisories/new) (the
Security tab, "Report a vulnerability"). Do not open a public issue for it.

Include the ziran version, the command or code that shows the problem, and its impact. We reply
in the advisory thread and publish the fix with a GitHub security advisory.

A vulnerability that ziran finds in an agent or tool you scan belongs to that project, not here.

## Verifying a release

Every release after v0.44.0 carries two
[GitHub artifact attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds),
signed through Sigstore by the release workflow:

- SLSA build provenance for the wheel, the sdist and the SBOM;
- a CycloneDX SBOM of the locked runtime packages, attested against the wheel and the sdist.

The SBOM file, `ziran-v<version>.cdx.json`, is attached to the GitHub release. The commands below
use the [GitHub CLI](https://cli.github.com/).

Verify the wheel you install from PyPI:

```bash
pip download ziran==<version> --no-deps --only-binary :all: -d ziran-dist
gh attestation verify ziran-dist/ziran-<version>-*.whl \
  --repo taoq-ai/ziran \
  --signer-workflow taoq-ai/ziran/.github/workflows/release.yml
```

Verify the SBOM file, and that the wheel's SBOM attestation holds:

```bash
gh release download v<version> --repo taoq-ai/ziran --pattern 'ziran-v<version>.cdx.json'
gh attestation verify ziran-v<version>.cdx.json --repo taoq-ai/ziran
gh attestation verify ziran-dist/ziran-<version>-*.whl \
  --repo taoq-ai/ziran \
  --predicate-type https://cyclonedx.org/bom
```

Each command exits 0 and prints the verified attestation when the file is the one the release
workflow built. PyPI also holds its own [PEP 740](https://peps.python.org/pep-0740/)
attestations for each file, made at upload through Trusted Publishing.
