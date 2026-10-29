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


# --- Mantiqiy tekshiruvlar ---
try:
    from sigma.data.mitre_attack import mitre_attack_techniques
except ImportError:  # pySigma versiyasida joyi boshqacha bo'lsa
    mitre_attack_techniques = None

# Sigma taksonomiyasidagi Windows kategoriyalari (kerak bo'lsa kengaytiriladi)
WINDOWS_CATEGORIES = {
    "antivirus", "application", "clipboard_capture", "create_remote_thread", "create_stream_hash",
    "dns_query", "driver_load", "file_access", "file_block_executable", "file_block_shredding",
    "file_change", "file_delete", "file_event", "file_executable_detected", "file_rename",
    "firewall", "image_load", "network_connection", "pipe_created", "process_access",
    "process_creation", "process_tampering", "ps_classic_provider_start", "ps_classic_start",
    "ps_module", "ps_script", "raw_access_thread", "registry_add", "registry_delete",
    "registry_event", "registry_rename", "registry_set", "sysmon_error", "sysmon_status",
    "wmi_event",
}


def unknown_techniques(collection: SigmaCollection) -> list[str]:
    """MITRE bazasida yo'q (to'qilgan yoki eskirgan) texnika ID'lari."""
    if mitre_attack_techniques is None:
        return []
    return [t for t in attack_techniques(collection) if t not in mitre_attack_techniques]


def bad_logsource(collection: SigmaCollection) -> str | None:
    """Windows uchun mavjud bo'lmagan kategoriya yozilgan bo'lsa, xabar qaytaradi."""
    for rule in collection.rules:
        ls = rule.logsource
        if ls.product == "windows" and ls.category and ls.category not in WINDOWS_CATEGORIES:
            return (
                f"logsource category '{ls.category}' does not exist in Sigma. "
                "For Windows Security/System event logs use product: windows and "
                "service: security (or system) with no category."
            )
    return None
