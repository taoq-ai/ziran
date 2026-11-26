# Tasks: document and image carriers

- [x] T001 Write the failing tests: builders and model validation in `tests/unit/test_carriers.py`,
  the three acceptance scenarios in `tests/unit/test_carrier_executor.py`; run red (collection
  failed: the modules did not exist).
- [x] T002 `Carrier` model on `AttackVector` and its parsing in `library.py`; `Attachment` and
  `attachment_types` on the adapter port.
- [x] T003 Builders in `application/attacks/carriers.py` (PDF, DOCX, HTML, PNG, metadata variants).
- [x] T004 `CarrierExecutor` and `CarrierSites`; delegation from `AttackExecutor`; scanner config key.
- [x] T005 Attachments in `AnthropicAdapter`, `HttpAgentAdapter` and `OpenAIProtocolHandler`.
- [x] T006 Opt-in selection in `AttackLibrary`; `ziran scan --carriers` (its three tests ran red
  without the CLI change, then green).
- [x] T007 Vectors in `vectors/document_carriers.yaml`, each with a reference; docs.
- [x] T008 Run the touched tests and `test_scanner_size.py` green, `ruff check`,
  `ruff format --check`, `mypy ziran/`.
- [x] T009 Gate fixes, round 1: plant and unlink synchronously inside the `try`/`finally` (a
  cancel test ran red first); the `--carriers` folders in the cache key; the dc_* vectors in the
  AML.T0086 fitness set; tests for the REST guard (no request sent), the exclusive create, the
  PNG glyphs, an all-failed vector, a dry run, and the page URL host check.
- [x] T010 Gate fixes, round 2: the plant cleanup also covers close (a full disk fails there for
  a buffered small file); tests for a failing write and a failing close (the close test ran red
  first); `page_url` needs an ASCII host with no userinfo.
