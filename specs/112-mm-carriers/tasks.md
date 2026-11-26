# Tasks: document and image carriers

- [ ] T001 Write the failing tests: builders and model validation in `tests/unit/test_carriers.py`,
  the three acceptance scenarios in `tests/unit/test_carrier_executor.py`; run red.
- [ ] T002 `Carrier` model on `AttackVector` and its parsing in `library.py`; `Attachment` and
  `attachment_types` on the adapter port.
- [ ] T003 Builders in `application/attacks/carriers.py` (PDF, DOCX, HTML, PNG, metadata variants).
- [ ] T004 `CarrierExecutor` and `CarrierSites`; delegation from `AttackExecutor`; scanner config key.
- [ ] T005 Attachments in `AnthropicAdapter`, `HttpAgentAdapter` and `OpenAIProtocolHandler`.
- [ ] T006 Opt-in selection in `AttackLibrary`; `ziran scan --carriers`.
- [ ] T007 Vectors in `vectors/document_carriers.yaml`, each with a reference; docs.
- [ ] T008 Run the touched tests and `test_scanner_size.py` green, `ruff check`,
  `ruff format --check`, `mypy ziran/`.
