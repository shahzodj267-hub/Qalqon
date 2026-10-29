# Qalqon architecture notes

## Rules of work
- One module at a time; each module is shipped working to GitHub.
- No API keys in git. Keys live in `.env`, template in `.env.example`.
- Every source module exposes `SUPPORTS` (set of IOC kinds) and `check(value, kind) -> dict`.
- Source errors inherit from `IntelError`; the aggregator catches them so one failing source does not break the result.

## Layout
- `core/config.py` - settings from `.env` (pydantic-settings)
- `modules/threat_intel/ioc.py` - `parse()` detects ip/domain/hash, `refang()` fixes `evil[.]com`
- `modules/threat_intel/{abuseipdb,virustotal,otx}.py` - source clients
- `modules/threat_intel/aggregator.py` - weights (0.4/0.4/0.2), risk per source, verdict
- `cli/main.py` - `python -m cli.main ioc <value>`

## Decisions
- Open-core: engine/CLI public, AI features, cloud panel, teams, API private/premium.
- AI provider must be swappable (cloud API or local LLM) for on-prem banks/government.
- ASM module: ownership verification (DNS TXT) and passive/permitted scanning only.
- Trial: 3 days on the cloud version (`role`, `trial_ends_at` fields), admin unlimited.

## Status
- [x] Module 1: threat intel CLI (IP, domain, hash)
- [x] Tests (pytest), CI (GitHub Actions)
- [ ] Web API
- [ ] Module 2: Detection Copilot

## Next task
Module 2: Detection Copilot.
