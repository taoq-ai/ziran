# Feature Specification: escape vector names and prompts in generated PoC scripts

**Feature Branch**: `fix/099-poc-quoting`
**Created**: 2026-11-24
**Status**: Active
**Plan item**: A-POC-QUOTING (goal G-a)

## The promise in our own words

`ziran/application/poc/generator.py` writes a Python PoC and a cURL PoC that a user runs by
hand. It pastes the vector name into a Python docstring, a shell comment and a shell `echo`, the
prompt's JSON into a single-quoted `-d '...'`, and the endpoint into a double-quoted default.
An apostrophe in a prompt closes the shell quote, so the rest of the prompt runs as shell
code; 160 of the 930 built-in prompts make the cURL script fail `bash -n`. A vector name, prompt
or endpoint from a custom attack library could inject code into the script the user runs.

After the fix, the scripts are safe to run whatever those values hold:

- The Python PoC holds every finding value (vector name and id, campaign id, category, severity,
  OWASP ids, prompt, indicators, the configured messages) as a `repr()` literal in a module
  constant. The docstring and the f-strings name no value.
- The cURL PoC holds every value as a `shlex.quote()`d shell word: the metadata, the default
  endpoint, the banner, the indicators. The JSON payload reaches curl through the `printf`
  builtin and `--data-binary @-`, so its bytes arrive unchanged and no argument size limit
  applies.

## Acceptance scenarios

1. **Given** a vector whose name, id and prompt hold `$(touch x)`, backticks, single and triple
   quotes, newlines, `\`, `{}` and `EOF` lines, **When** its PoC scripts are generated and run
   (the Python one against a stub adapter, the shell one with a stub `curl` first on `PATH`),
   **Then** no marker file appears and the payload arrives byte for byte.
2. **Given** every built-in vector prompt (930), **When** its PoC scripts are generated, **Then**
   each Python script compiles and each shell script passes `bash -n`.

## Requirements

- FR-001: No finding value appears in the Python PoC outside a `repr()` literal.
- FR-002: No finding value or endpoint appears in the cURL PoC outside a `shlex.quote()` word.
- FR-003: The cURL body is exactly `json.dumps({"message": prompt})`.
- FR-004: Indicators match as fixed strings (`grep -qiF --`), the same substring test the Python
  PoC runs.

## Assumptions

- The template settings an operator writes in its own PoC YAML (shebang, imports) are trusted
  code, as before; the message texts are now quoted too. Overturned if PoC config ever comes
  from an untrusted source.
- `grep -F` replaces regex matching of indicators. Indicators are literal strings and the
  Python PoC already matches them as substrings. Overturned if a caller relies on regex
  indicators.
- The built-in check uses each prompt's raw template; the rendered prompt only fills `{var}`
  slots with the vector's own defaults.
- `vector_id` and `campaign_id` in the output file names are out of this item's scope (a path
  candidate, reported separately).
