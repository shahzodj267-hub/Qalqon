import re

import yaml
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

BACKENDS = {"splunk": SplunkBackend, "kql": KustoBackend}
TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)


class RuleError(Exception):
    """Sigma qoidasi noto'g'ri yoki tarjima qilib bo'lmadi."""


def load(yaml_text: str) -> SigmaCollection:
    try:
        return SigmaCollection.from_yaml(yaml_text)
    except (SigmaError, yaml.YAMLError) as e:
        raise RuleError(f"Sigma qoidasi noto'g'ri: {e}") from e


def attack_techniques(collection: SigmaCollection) -> list[str]:
    """attack.t1105 kabi teglardan MITRE texnikalarini ajratadi."""
    found = []
    for rule in collection.rules:
        for tag in rule.tags:
            if tag.namespace == "attack" and TECHNIQUE_RE.match(tag.name):
                found.append(tag.name.upper())
    return found


def convert(collection: SigmaCollection, target: str) -> list[str]:
    backend = BACKENDS[target]()
    try:
        return backend.convert(collection)
    except SigmaError as e:
        raise RuleError(f"{target}: {e}") from e
