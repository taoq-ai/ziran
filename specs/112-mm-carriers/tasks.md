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
