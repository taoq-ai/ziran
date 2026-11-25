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
- `vector_id` and `campaign_id` also form the PoC file names. A `/` or `..` in either wrote
  outside the output folder. Each is now reduced to `[A-Za-z0-9._-]` (anything else becomes
  `_`), an empty or dot-only value is refused, and the final path must resolve to a file
  directly inside the output folder. Every file is written to a new temp file in the folder
  and moved onto its name with `os.replace`, and the Markdown guide is written by ZIRAN itself.
  So the checked name is the name written, and a symlink, hard link or FIFO planted at that name
  is replaced, never written through or waited on. File modes follow the umask; only the `.sh`
  PoC is forced to `0755`, as before.
- Banners print the vector name with non-printable characters escaped, so an ESC, C1 or bidi
  sequence in a name cannot drive the terminal. curl takes the endpoint as `--url`.

## Acceptance scenarios

1. **Given** a vector whose name, id and prompt hold `$(touch x)`, backticks, single and triple
   quotes, newlines, `\`, `{}` and `EOF` lines, **When** its PoC scripts are generated and run
   (the Python one against a stub adapter, the shell one with a stub `curl` first on `PATH`),
   **Then** no marker file appears and the payload arrives byte for byte.
2. **Given** a `vector_id` or `campaign_id` of `../x`, an absolute path, a NUL or a space,
   **When** the Python, cURL and Markdown files are written, **Then** each lands directly in
   the output folder under a `[A-Za-z0-9._-]` name, and nothing is written elsewhere.
3. **Given** an empty or dot-only `vector_id` or `campaign_id`, **When** a PoC file is written,
   **Then** a `ValueError` is raised and no file is written.
4. **Given** a symlink, hard link or FIFO planted at a PoC file name, or a `campaign_id` of
   `x.md` with a link at `poc_guide_x.md`, **When** the files are written, **Then** the link
   target is unchanged and the write does not hang.
5. **Given** `umask 077`, **When** the three files are written, **Then** the `.py` and `.md`
   files are `0600` and the `.sh` file is `0755`.
6. **Given** every built-in vector prompt (930), **When** its PoC scripts are generated, **Then**
   each Python script compiles and each shell script passes `bash -n`.

## Requirements

- FR-001: No finding value appears in the Python PoC outside a `repr()` literal.
- FR-002: No finding value or endpoint appears in the cURL PoC outside a `shlex.quote()` word.
- FR-003: The cURL body is exactly `json.dumps({"message": prompt})`.
- FR-004: Indicators match as fixed strings (`grep -qiF --`), the same substring test the Python
  PoC runs.
- FR-005: Every PoC file name part passes `_safe_name`, and `PoCGenerator._path` refuses a
  path whose resolved parent is not the output folder.
- FR-006: Every PoC file is written as UTF-8 to an `O_EXCL` temp file in the output folder and
  moved onto its name with `os.replace`; only an executable mode is forced past the umask.
- FR-007: No banner prints a non-printable character of the vector name raw.

## Assumptions

- The template settings an operator writes in its own PoC YAML (shebang, imports) are trusted
  code, as before; the message texts are now quoted too. Overturned if PoC config ever comes
  from an untrusted source.
- `grep -F` replaces regex matching of indicators. Indicators are literal strings and the
  Python PoC already matches them as substrings. Overturned if a caller relies on regex
  indicators.
- The built-in check uses each prompt's raw template; the rendered prompt only fills `{var}`
  slots with the vector's own defaults.
- Refusing (a `ValueError`) is right for an empty or dot-only id: no file name stands for it,
  and the scanner always sets both ids. Overturned if a real campaign ever has an empty id.
- Two ids that differ only in replaced characters now share a file name, and the later file
  wins. Overturned if a library ships such ids.
