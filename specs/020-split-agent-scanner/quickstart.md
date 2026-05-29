# Quickstart: Split AgentScanner

## Usage (unchanged — this is a refactor)

```python
from ziran.application.agent_scanner import AgentScanner, ProgressEvent, ProgressEventType

scanner = AgentScanner(adapter=adapter, attack_library=library)
result = await scanner.run_campaign(phases=None, stop_on_critical=True)
```

## New: Testing Individual Components

### Test attack execution in isolation

```python
from ziran.application.agent_scanner.attack_executor import AttackExecutor

executor = AttackExecutor(adapter=mock_adapter, detector_pipeline=pipeline, config={})
result = await executor.execute(attack_vector)
```

### Test phase execution in isolation

```python
from ziran.application.agent_scanner.phase_executor import PhaseExecutor

phase_exec = PhaseExecutor(attack_executor=atk_exec, config={})
phase_result = await phase_exec.execute_phase(phase, vectors, progress_emitter)
```

### Test result building in isolation

```python
from ziran.application.agent_scanner.result_builder import ResultBuilder

campaign_result = ResultBuilder.build_campaign_result(
    campaign_id="test", target_agent="test", phase_results=[], graph=graph
)
```
