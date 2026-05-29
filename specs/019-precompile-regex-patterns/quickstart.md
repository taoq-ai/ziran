# Quickstart: Pre-compile Regex Patterns

## Usage (unchanged — this is a performance optimization)

```python
from ziran.application.static_analysis.config import StaticAnalysisConfig
from ziran.application.static_analysis.analyzer import StaticAnalyzer

config = StaticAnalysisConfig.default()
analyzer = StaticAnalyzer(config=config)
findings = analyzer.analyze_file(Path("my_agent.py"))
```

## What Changed Internally

Patterns are now pre-compiled at config load time. No API changes.

```python
# Before: compiled per file, per check (in _run_check)
compiled = [re.compile(p.pattern) for p in check.patterns]

# After: compiled once at config load (in model validator)
# _run_check uses check.compiled_patterns directly
```

## Verifying the Optimization

```python
config = StaticAnalysisConfig.default()
# Patterns are already compiled
for check in config.secret_checks:
    assert all(hasattr(p, 'compiled') for p in check.patterns)
```
