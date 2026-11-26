# CycloneDX 1.6 JSON schema (test fixture)

The official CycloneDX 1.6 JSON schema with the two schemas it references, used by
`tests/unit/test_aibom.py` to validate the AI-BOM that `ziran audit --aibom` writes.

- Source: the CycloneDX specification (https://github.com/CycloneDX/specification), Apache-2.0,
  as shipped in `cyclonedx-python-lib` 11.12.0 (`cyclonedx/schema/_res/`).
- Change: the files are renamed from `*.SNAPSHOT.schema.json` to the upstream names, and the two
  `$ref` values in `bom-1.6.schema.json` with them. Nothing else is edited.
