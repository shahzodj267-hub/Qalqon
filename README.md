# Qalqon 🛡️

**Security operations toolkit that turns scattered threat intelligence into one clear verdict.**

Qalqon ("shield" in Uzbek) is an open-core platform for SOC analysts, pentesters and security teams. It is being built module by module, starting with threat intelligence.

> **Status:** early development. Module 1 (Threat Intel) works from the CLI.

## The problem

Analysts check every suspicious IP, domain or file hash in 3-5 different tools, compare the results by hand, and still have to decide who to trust. One source can be wrong or misleading, so Qalqon queries several and combines them.

## Quick start

```bash
git clone git@github.com:shahzodj267-hub/Qalqon.git
cd Qalqon
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then add your free API keys
python -m cli.main ioc 185.220.101.4
```

## Example


## Features

- [x] IP, domain and file hash (MD5/SHA1/SHA256) lookups, type detected automatically
- [x] Sources: AbuseIPDB, VirusTotal, AlienVault OTX
- [x] Weighted risk score, with a floor when one source is very confident
- [x] A failing source never breaks the whole check
- [x] Defanged input support (`evil[.]com`)

## Roadmap

- [ ] Unit tests and CI
- [ ] Web API (FastAPI) and web panel
- [ ] AI-generated summaries (cloud or local LLM)
- [ ] Detection Copilot: plain language to Sigma / SPL / KQL / YARA with MITRE ATT&CK mapping
- [ ] Pentest findings aggregation and report generation
- [ ] Attack surface monitoring (ownership-verified domains only)
- [ ] On-premise deployment with a local LLM for regulated environments (banks, government)

## Tech

Python, Typer, httpx, FastAPI, SQLAlchemy, pydantic-settings, Docker.

## Security

API keys live in `.env` and are never committed. Qalqon only queries third-party intelligence APIs, it does not scan targets.

## Author

Built by [@shahzodj267-hub](https://github.com/shahzodj267-hub).
