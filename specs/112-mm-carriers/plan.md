# Implementation Plan: document and image carriers

**Branch**: `feat/112-mm-carriers` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13), Pydantic v2, stdlib `zipfile`, `zlib`, `struct`,
`base64`, `html`, `xml.sax.saxutils`, `textwrap`, `secrets`. No new dependencies.

## Constitution check

- Hexagonal: the `Carrier` model is a domain entity (`domain/entities/attack.py`); `Attachment`
  and `attachment_types` extend the adapter port (`domain/interfaces/adapter.py`). The builders
  and the executor are application code (`application/attacks/`). Adapters implement the port.
- Types: mypy strict; `Carrier` and `CarrierSites` are Pydantic models with `extra="forbid"`.
- Size budgets: `attack_executor.py` (399/400) gains one delegation branch and loses three
  redundant comments; `scanner.py` (749/750) passes one config key and loses a two-line comment.
  New logic goes in new modules outside `agent_scanner/`.
- Vectors are YAML (`vectors/document_carriers.yaml`), each with a source reference.
- Async: planting and cleanup run in `asyncio.to_thread`.

## Design

- `Carrier` on `AttackVector`: `format` (pdf, docx, html, png), `placement` (body, metadata),
  `delivery` (workspace, knowledge_base, page, attachment), `name`, `cover`, `text`. A validator
  requires `tactic: single` and `{carrier}` in every prompt.
- `application/attacks/carriers.py`: `build(carrier) -> Attachment`, one function per format,
  a 5x7 bitmap font for the PNG.
- `application/attacks/carrier_executor.py`: `CarrierSites` (the folders and the page URL) and
  `CarrierExecutor.execute(attack, pipeline, render)`. It works out why the vector cannot run
  (no folder, or a media type the adapter lacks) and skips as unmeasured; otherwise it plants
  or attaches, sends each prompt with `{carrier}` filled in, sets the payload to the hidden text
  (`scan_metadata`), runs the unchanged detector pipeline and records `carrier` in the evidence.
- `AttackExecutor(carriers=...)` delegates a carrier vector to `CarrierExecutor`.
- `AttackLibrary(carriers=False)`: `get_attacks_for_phase` leaves carrier vectors out unless set.
- Adapters: `AnthropicAdapter` sends `image` and `document` base64 blocks; `HttpAgentAdapter`
  reports `image/png` on the OpenAI protocol and `OpenAIProtocolHandler.send` adds `image_url`
  data-URI parts. Both refuse a media type they do not list.
- CLI: `ziran scan --carriers <yaml>` loads `CarrierSites` and turns carrier vectors on; a bad
  file is a usage error.

## Test plan

- `tests/unit/test_carriers.py`: builders (PDF xref offsets, DOCX parts, HTML escaping, PNG CRC
  and pixels, metadata variants), model validation, and a ReDoS probe of the stem pattern.
- `tests/unit/test_carrier_executor.py`: the three acceptance scenarios with a file-reading
  `MockAgentAdapter`, the real `DetectorPipeline`, attachment requests through the Anthropic
  adapter and the OpenAI handler on `httpx.MockTransport`, and the skip rows.
- `tests/unit/test_attack_library.py`: carrier vectors load, have references and are opt-in.
