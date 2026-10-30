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

## Module 2: log testing
- `modules/detection/evaluator.py` - own minimal Sigma evaluator (contains/startswith/endswith/all/re, wildcards, and/or/not, `1 of x*`). Unsupported features raise EvaluationError, never silently pass.
- `modules/detection/tester.py` - runs a rule over sample events, reports hits, false positives and fields that appear in no event.
- Sample data: `rules/samples/benign_process_creation.yml` (shared benign corpus), `rules/tests/*.yml` (attack + benign events per scenario).
- CLI: `rule test <rule.yml> <events.yml>`, `rule generate "<text>" --logs <events.yml>`
- Limits: logsource is not checked; passing only means passing the sample events; no correlation/aggregation.

## Module 2: log testing
- `modules/detection/evaluator.py` - own minimal Sigma evaluator. Unsupported features raise EvaluationError, never silently pass.
- `modules/detection/tester.py` - runs a rule over sample events: hits, false positives, fields missing from all events.
- Sample data: `rules/samples/benign_process_creation.yml` (shared benign corpus), `rules/tests/*.yml`.
- CLI: `rule test <rule.yml> <events.yml>`, `rule generate "<text>" --logs <events.yml>`
- Limits: logsource not checked; passing only means passing the sample events; no correlation/aggregation.

## Module 2: auto-fix loop (results 2026-10-30, local qwen2.5-coder:7b)
- generate --logs: failed log test is fed back to the model (3 attempts); failing report exits with code 1.
- PowerShell -enc: not fixed in 3 attempts (model repeated the same rule). Office and local-admin rules passed.
- Known gaps: Office example in the prompt is nearly identical to the test (memorized); MITRE check verifies the ID exists, not that it fits the behavior (t1098.001 accepted for local admin add); tests are visible to the model (no hidden set yet).

## Benchmark (rules/bench, `bench run --model X`)
4 scenarios, visible events (shown to the model) + hidden events (final check). PASS needs both.
First run 2026-10-30, single run each, qayta urinishlarda temperature 0.7 (later reverted to 0.2):
- qwen2.5-coder:7b 3/4 (ps_enc failed: hidden attacks 1/2, hidden false positives 1/2)
- mistral 1/4, llama3 0/4 (mostly invalid YAML)
Caveats: 4 scenarios written by the author; `office` description is close to a prompt example; `local_admin` description gives the EventID; one run per model; the 0.7 retry temperature probably hurt llama3/mistral.

## Benchmark results, retry temperature back at 0.2 (2026-10-30)
Two runs per model (qwen and mistral were identical both times: near-deterministic at 0.2).
- qwen2.5-coder:7b: 2/4 (certutil, office pass; local_admin generation error; ps_enc FAIL)
- mistral: 2/4 (certutil, office pass; local_admin YAML error; ps_enc FAIL)
- llama3: 0/4 (mostly invalid YAML)
ps_enc fails on all three models: `-enc` substring also matches `-Encoding`, and pwsh.exe is missed (description does not mention pwsh, so the scenario may be strict).
Not conclusive: 4 author-written scenarios; `office` resembles a prompt example; `local_admin` description gives the EventID; retry-temperature change (0.7 vs 0.2) moved single scenarios in both directions.
Takeaway: local 7B/8B models are not a reliable rule writer on their own; the validation + log-test pipeline is what prevents bad rules from being reported as ready. Cloud model comparison pending.
