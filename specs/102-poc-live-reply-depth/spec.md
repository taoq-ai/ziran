# Feature Specification: A generated PoC reads a deeply nested live reply without a traceback

**Feature Branch**: `fix/poc-live-reply-depth`
**Created**: 2026-11-25
**Status**: Active
**Plan item**: C-POC-LIVE-REPLY (goal G-c)

## The promise in our own words

The httpx Python PoC parses the agent's live reply with `reply.json()` and walks it with a
recursive `_texts`. A hostile agent can answer with JSON nested thousands of lists deep. No
Python decodes 100000 deep, and Python 3.11 cannot decode 5000 deep: `reply.json()` raises
`RecursionError`. Python 3.12 and later decode 5000 deep, and then the recursive walk raises
`RecursionError`. Either way the script dies with a traceback and exits 1, the code that
means "not reproduced". So a reply the PoC could not read looks like a fixed agent.

After the fix:

- `_texts` walks the parsed reply with a loop and a stack, in the same order as before, so a
  reply nested deeper than the stack is still read.
- When `reply.json()` raises `RecursionError`, the script prints
  `[-] Unreadable reply: its JSON nests too deep to parse` and exits 3.
- A reply that is not JSON (`ValueError`) is still matched as plain text, as before.
- Exit codes 0, 1 and 2 keep their meaning. The cURL PoC greps the raw body and is unchanged.
- `docs/reference/cli.md` lists exit 3.

## Acceptance scenarios

1. Given a stub that replies with JSON 100000 lists deep, when the Python PoC runs with
   `python -I`, then it prints the unreadable-reply message and exits 3, with no traceback.
2. Given a stub that replies with JSON 5000 lists deep around the canary, when the Python PoC
   runs, then it exits 3 with the message on Python 3.11 and exits 0 (canary found) on 3.12
   and later, never with a traceback.
3. Given a normal reply, the PoC exits 0 on a leak and 1 on a fixed agent, as before.
4. Given the same deep replies, the cURL PoC still exits 0 when the canary is in the body.

## Assumptions

- `ValueError` keeps its current meaning (a non-JSON reply read as text), not exit 3: a plain
  text agent is a normal target. Overturned if the owner wants any non-JSON reply flagged.
- Exit 3 is only for a reply that cannot be decoded. A 5000-deep reply that 3.12 decodes is
  readable, so its verdict follows the indicators; the result depends on the interpreter's
  JSON decoder, which the docs state as "nested too deep to parse".
