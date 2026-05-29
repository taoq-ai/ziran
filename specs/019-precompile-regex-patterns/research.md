# Research: Pre-compile Regex Patterns

## Decision 1: Compilation Strategy

**Decision**: Eager compilation via Pydantic `model_validator` (or `@computed_field`) on the config models.

**Rationale**: Compiling patterns eagerly at model construction time surfaces invalid regex errors immediately at config load time, rather than at first file analysis. Pydantic's `model_validator(mode="after")` is the idiomatic way to derive computed fields after model validation.

**Alternatives considered**:
- `functools.lru_cache` on `re.compile()` — Python already caches the last 512 compiled patterns, but this is implicit, fragile (eviction under load), and doesn't surface errors early.
- `@cached_property` on `CheckDefinition` — Would work but Pydantic models require special handling for non-field attributes. `model_validator` is cleaner.
- Compile in `_run_check()` with a module-level cache dict — Moves state management outside the model. Less clean.

## Decision 2: Storage of Compiled Patterns

**Decision**: Store compiled patterns in a non-serialized field (`exclude=True` in Pydantic) so they don't interfere with YAML serialization or model comparison.

**Rationale**: Compiled `re.Pattern` objects are not JSON/YAML serializable. Marking the field as excluded keeps serialization clean while allowing the compiled patterns to be used at runtime.

## Decision 3: DangerousToolCheck and InputValidationCheck

**Decision**: Apply the same pattern to all check types — `DangerousToolCheck.compiled_pattern` and `InputValidationCheck.compiled_tool_pattern` / `compiled_validation_pattern`.

**Rationale**: Consistency across all check types. Even though `InputValidationCheck` runs once per file (not per line), pre-compiling keeps the pattern uniform and surfaces errors early.
