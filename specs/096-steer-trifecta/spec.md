# Feature Specification: aim chain vectors at the lethal trifecta, refuse credential files, swap whole host names

**Feature Branch**: `feat/096-steer-trifecta`
**Created**: 2026-11-24
**Status**: Active
**Plan item**: A-STEER-TRIFECTA (goal G-a). Refs #536. Follow-ups the #548 gates named.
**Base**: `develop` @ dfdbe96.

## The promise in our own words

Spec 087 steers the campaign at the chains found at discovery. Three gaps in
`ziran/application/agent_scanner/chain_targeting.py` are closed here:

1. A flat agent with `read_inbox`, `get_customer` and `send_email` shows one chain, the
   `lethal_trifecta` (spec 088), and today no family row maps it, so it gets no aimed vector.
   The exfiltration family now also takes any chain type with a `trifecta` token
   (`lethal_trifecta`, `lethal_trifecta_delegated`). It shares that family's ranked pool, so no
   vector renders for two chains. The chain's source and sink are the first `private_data` and
   the first `egress` tool in its evidence, not `tools[0]` and `tools[-1]`, because trifecta
   tools are kept in tool order. When the sink sends mail, the task names a mail address on the
   reserved endpoint host instead of the upload URL.
2. A credential file is never the steered resource. `_names_secret` also matches the secret
   path pattern of `tool_aliases.py` (made public as `SECRET_PATH`, `/etc/shadow` added) on
   each path-like token of the raw text, so `_resource` and `_render` use one check. Audit then
   also maps `Read(/etc/shadow)` to `read_secret_file`.
3. `swap` (indicators and description) rewrites a mapped host only as a whole host name:
   `devil.company`, `evil.com.au` and `notevil.com` stay as they are when `evil.com` is mapped.

## Acceptance scenarios

1. **Given** a flat agent with `read_inbox`, `get_customer` and `send_email`, **When**
   `plan_steering` runs at standard coverage, **Then** a `lethal_trifecta` target lists 1 to 5
   vectors, every rendered prompt names a private data leg tool and `send_email`, and no vector
   id sits under two targets.
2. **Given** a `read_file` schema default of `.env`, `/etc/shadow`, `certs/server.pem`,
   `~/.ssh/config` or `~/.netrc`, **When** `_resource` runs, **Then** it returns `notes.txt`,
   and `_render` of a prompt naming any of them returns None.
3. **Given** a vector whose prompt links `https://evil.com/x`, with indicators `devil.company`,
   `evil.com.au` and `sent to evil.com` and description `mail notevil.com`, **When** it renders,
   **Then** the indicators read `devil.company`, `evil.com.au` and
   `sent to reports.example.invalid`, and the description is unchanged.
4. **Given** the change, **When** `test_scanner_size.py` and `test_chain_targeting.py` run,
   **Then** both pass, `chain_targeting.py` is at most 400 lines, and the flat `read_file` to
   `http_request` exfiltration chain still gets its vectors.

## Requirements

- **FR-001**: `_FAMILIES`' exfiltration row's prefixes include `trifecta`.
- **FR-002**: a chain whose evidence lists `private_data` and `egress` tools takes its source and
  sink from the first of each; otherwise `tools[0]` and `tools[-1]`.
- **FR-003**: when the sink's name contains `mail`, the exfiltration task names
  `reports@reports.example.invalid` in place of the upload URL.
- **FR-004**: `tool_aliases.SECRET_PATH` is public and matches `/etc/shadow`;
  `_names_secret` returns True when any path-like token of the raw text matches it.
- **FR-005**: `swap` replaces a mapped host only where no host character comes before it and no
  host character or `.label` comes after it.
- **FR-006**: the PR records how many library vectors the wider check newly skips at standard
  coverage.

## How this fails

1. The trifecta chain comes first (critical) and draws five exfiltration vectors that the
   `data_exfiltration` chains of a richer agent used to get. The pool is shared, so the union
   of chosen vectors is unchanged or grows; the hand-reviewed `CHOSEN` pins catch any change.
2. The token check over-matches prose (a word ending `.key`), so a useful vector is skipped. The
   library count (FR-006) is 0 at standard and comprehensive coverage, so no shipped vector is lost.
3. An anchored swap misses a host the old substring swap caught (a host glued to a word), and
   an indicator keeps the attacker host, so a reply naming the endpoint does not score. The
   prompt-side `_HOST.sub` is unchanged, and the shipped `de_markdown_link` scoring test stays.

## Outside

New vector categories, which chains the analyzer finds, `scanner.py` and `attack_executor.py`.

## Assumptions

- The path check runs per token (split on whitespace, quotes, brackets and `,;:=?!*`, a trailing
  dot dropped) rather than on the whole text. Why: `SECRET_PATH` anchors `.env` to the start or a
  `/` or `~` and the key suffixes to the end, which fits a permission spec but never matches a
  path inside a sentence. Splitting keeps the audit pattern as it is, `/etc/shadow` aside.
  Overturn: a path the split misses in a shipped vector.
- The mail address applies to any exfiltration chain whose sink name contains `mail`, not only
  the trifecta. Why: the upload URL is the wrong target for a mail tool on any chain. Overturn:
  a pinned prompt set the owner wants kept.
- The host swap is case-insensitive. Why: host names are; the old swap was not. Overturn: none
  known.
