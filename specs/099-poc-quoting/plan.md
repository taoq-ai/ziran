# Plan: escape vector names and prompts in generated PoC scripts

One file changes: `ziran/application/poc/generator.py`. No new dependency (`shlex` is stdlib).

- Python PoC: a static docstring, then module constants (`VECTOR_NAME`, `CAMPAIGN_ID`, ...,
  `ATTACK_PROMPT`, `SUCCESS_INDICATORS`, the three messages) filled with `repr()`. Prints read
  the constants. `vulnerable_text_match` keeps its `{matched}` slot through `.format(matched=)`.
  The run instructions print `repr()` literals. `_escape_python_string` goes (no other caller).
- cURL PoC: metadata as quoted shell assignments, `DEFAULT_ENDPOINT=<quoted>` and
  `ENDPOINT="${1:-$DEFAULT_ENDPOINT}"`, the banner through `printf '%s\n' <quoted>`, the body
  through `printf '%s' <quoted json> | curl --data-binary @-`, indicators through
  `grep -qiF -- <quoted>`.
- Files are written as UTF-8.
- File names: `_safe_name` replaces anything outside `[A-Za-z0-9._-]` with `_` and refuses an
  empty or dot-only value; `PoCGenerator._path` checks the resolved parent is the output
  folder. The Python, cURL and Markdown writers all go through both.

Tests in `tests/unit/test_poc_generator.py`: the hostile vector run end to end with a marker
file, a stub adapter and a stub `curl`; every built-in prompt through `compile()` and `bash -n`.
Mutants on each escape run under `timeout -s KILL 120`.
