# Data Model: Pre-compile Regex Patterns

This is a pure optimization — no new entities. Existing entities gain compiled pattern fields.

## Modified Entities

| Entity | Current Fields | New Field | Notes |
|--------|---------------|-----------|-------|
| `PatternRule` | `pattern: str`, `description: str` | `compiled: re.Pattern` | Compiled from `pattern` at construction |
| `CheckDefinition` | `patterns: list[PatternRule]`, ... | `compiled_patterns: list[re.Pattern]` | Derived from `patterns` list |
| `DangerousToolCheck` | `pattern: str`, ... | `compiled_pattern: re.Pattern` | Compiled from `pattern` at construction |
| `InputValidationCheck` | `tool_definition_pattern: str`, `validation_pattern: str` | `compiled_tool_pattern: re.Pattern`, `compiled_validation_pattern: re.Pattern` | Both compiled at construction |

## Dependency Graph (unchanged)

```
StaticAnalysisConfig
├── CheckDefinition (multiple lists)
│   └── PatternRule
├── DangerousToolCheck
└── InputValidationCheck
```
