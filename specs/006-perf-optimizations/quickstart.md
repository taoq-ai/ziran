# Quickstart: Performance Optimizations

## What Changed

1. **YAML parsing** uses the C-accelerated loader (CSafeLoader) with automatic fallback
2. **Library caching** via `get_attack_library()` singleton factory — avoids re-parsing YAML on every call
3. **Benchmark iterations** reduced from 3 to 1 (warm-up run still provides cold-start elimination)
4. **Chain analysis** pre-filters tool pairs and checks reachability before expensive graph searches

## Usage

### Attack Library (callers)

```python
# Before (creates a new instance every time, re-parses 24 YAML files):
from ziran.application.attacks.library import AttackLibrary
lib = AttackLibrary()

# After (returns cached singleton for default config):
from ziran.application.attacks.library import get_attack_library
lib = get_attack_library()

# Still works for custom config (returns fresh instance):
lib = get_attack_library(custom_dirs=[Path("/my/vectors")])
```

### Chain Analysis (no API changes)

Chain analysis performance is improved internally. No caller changes needed.

## Verification

```bash
cd src
ruff check .
python -m mypy ziran/ benchmarks/
pytest tests/ -x
```
