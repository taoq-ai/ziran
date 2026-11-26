# Plan: policy export escapes tool names and emits OPA 1.0 Rego

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Stdlib `json` for the literals; `printable` from
`ziran/domain/text.py` for comments. New test-group dependency: `cedarpy` (wheels for 3.11 to
3.13), used only to parse Cedar output in tests. CI installs OPA 1.x with
`open-policy-agent/setup-opa`.

## Constitution check

- Hexagonal: the infrastructure renderers import `printable` from the domain. Pass.
- Types: annotated, mypy strict clean. Pass.
- Tests: `tests/unit/test_policy_renderer_escaping.py` renders one hostile tool set through
  each renderer and parses the output with the language's own parser where one exists. Pass.
- Simplicity: no new module. Invariant and Colang share `quoted` beside `printable` in
  `ziran/domain/text.py`; Rego has `_rego_str` and Cedar `_cedar_str`. Pass.

## Design

1. `rego_renderer.py`: `import rego.v1`, `deny contains msg if {`; tool terms and the message
   as `_rego_str` JSON literals; finding id, chain and severity comments through `printable`.
2. `invariant_renderer.py` and `colang_renderer.py`: the message and each `ToolCall` argument
   as `quoted` literals; the finding id comment through `printable`. The Colang flow name
   is already reduced to `[a-z0-9_]` by `_sanitize`.
3. `cedar_renderer.py`: `_cedar_str` escapes `"` and `\` with a backslash and writes every
   non-printable character as `\u{hex}`; the resource id and `context.previous_tool` use it;
   the finding id comment goes through `printable`. The two-tool limit is unchanged.
4. CI: `test.yml` and `release.yml` add `setup-opa` (version `1.x`) before pytest.
5. `specs/011-runtime-bridge-v0-8/research.md`: the Rego structure line names the 1.0 syntax.
