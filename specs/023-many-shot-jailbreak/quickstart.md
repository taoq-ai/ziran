# Quickstart: Many-Shot Jailbreaking Vector Category

## See the vectors in the library

```bash
uv run python -c "
from ziran.application.attacks.library import AttackLibrary
lib = AttackLibrary()
ms = [v for v in lib.vectors if v.many_shot]
print(f'{len(ms)} many-shot vectors')
for v in ms[:3]:
    print(' ', v.id, '| harm:', v.harm_category, '| n_shots:', v.many_shot.n_shots)
"
```

## Render a many-shot prompt and check it scales

```bash
uv run python -c "
from ziran.application.attacks.many_shot import ShotRenderer
r = ShotRenderer()
small = r.render('cybercrime', 10)
big = r.render('cybercrime', 100)
print('10 shots  ~', r.estimate_tokens(small), 'tokens')
print('100 shots ~', r.estimate_tokens(big), 'tokens')   # expect >= 50000
assert len(big) > len(small)            # scales with n
assert r.render('cybercrime', 100) == big   # deterministic
print('clamp 9999 ->', r.clamp(9999))   # (500, True)
"
```

## Run a scan with a shot-count override

```bash
# Override every many-shot vector's shot count for a sweep (e.g. via the scanner config).
# (The scan-time override sets config["n_shots"]; context_window controls the skip-on-overflow.)
uv run ziran scan --framework langchain --agent-path ./agent.py
```

## Acceptance walkthrough (maps to spec Success Criteria)

1. **SC-001** — the library exposes ≥10 many-shot vectors across multiple harm categories, each with OWASP LLM01 + ATLAS `AML.T0054`/`AML.T0065`.
2. **SC-002** — `ShotRenderer.render(key, 100)` estimates ≥50,000 tokens; rendering at higher counts yields proportionally longer prompts.
3. **SC-003** — default is 50; counts below 1 or above ~500 are clamped to the bound with a warning, never empty/unbounded.
4. **SC-004** — with a small `context_window`, a many-shot vector is skipped and a warning recorded (the over-capacity prompt is not sent).
5. **SC-005** — the coverage report (`benchmarks/generate_all.py` → `coverage-comparison.md`) shows a `many-shot` tag.
6. **SC-006** — `render(key, n)` is identical across calls (reproducible).

## Quality gates (before PR)

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy ziran/
uv run pytest --cov=ziran        # all pass, coverage >= 85%
```

## Where things live

| Concern | Path |
|---------|------|
| `ManyShotConfig` + `AttackVector.many_shot` | `ziran/domain/entities/attack.py` |
| Shot renderer (clamp / estimate / render) | `ziran/application/attacks/many_shot.py` |
| Vectors | `ziran/application/attacks/vectors/many_shot_jailbreak.yaml` |
| Synthetic shot corpus | `ziran/application/attacks/vectors/many_shot_corpus.yaml` |
| Executor expansion + skip/warn | `ziran/application/agent_scanner/attack_executor.py` |
| Config threading | `ziran/application/agent_scanner/scanner.py` |
| Coverage tag | `benchmarks/inventory.py` + `generate_all.py` |
| Docs | `docs/concepts/attack-vectors.md` (Long-context attacks) |
