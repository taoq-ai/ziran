# Plan: spec 119

Add `new_campaign_id()` to `ziran/application/agent_scanner/scanner.py` (stdlib `secrets`) and call it where the id was built. Resume still overwrites the id from the checkpoint. Tests in `tests/unit/test_scanner.py`.
