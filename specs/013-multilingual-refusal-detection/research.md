# Research: Multilingual Refusal Detection

## R1: Refusal pattern curation approach

**Decision**: Curate patterns from observed LLM refusal outputs in each target language.
**Rationale**: Major LLMs (Claude, GPT, Gemini) produce consistent, recognizable refusal phrases in non-English languages. These phrases follow predictable structures — apology + inability statement + ethical/policy reasoning. Pattern matching against these structures is sufficient without NLP.
**Alternatives considered**:
- Machine translation of English patterns — rejected: translations don't match actual LLM output (e.g., "I cannot" doesn't translate to the same refusal phrasing LLMs actually use).
- External language detection library — rejected: adds dependency for no benefit; pattern matching across all configured languages is simpler and faster.

## R2: CJK pattern matching in Python `re`

**Decision**: Use Python's `re` module directly for Chinese and Japanese patterns.
**Rationale**: Python's `re` module supports Unicode natively. CJK characters work correctly with `re.IGNORECASE` (though CJK has no case distinction, the flag doesn't harm). No special handling needed.
**Alternatives considered**:
- `regex` third-party module — rejected: unnecessary dependency; stdlib `re` handles all our patterns.

## R3: Mega-regex performance with multilingual patterns

**Decision**: Compile a single combined mega-regex at init time, same approach as current English-only implementation.
**Rationale**: Adding ~60-90 patterns (10-15 per language x 6 languages) to the existing ~94 English patterns brings the total to ~154-184 alternations. Python's `re` module handles this efficiently — the compilation cost is paid once at init, and matching performance scales sub-linearly with alternation count due to regex engine optimizations.
**Alternatives considered**:
- Separate regex per language — rejected: would require running multiple regex matches per detection call, slower than a single combined regex.
- Aho-Corasick library — rejected: unnecessary dependency for pattern counts under 200.

## R4: English always included

**Decision**: English patterns are always included regardless of `languages` parameter.
**Rationale**: Prevents accidental misconfiguration where a user sets `languages=["es"]` and loses English detection. English is the baseline and should never be removable.
