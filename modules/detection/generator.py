import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date

import yaml

from core.ai import Provider, get_provider
from modules.detection import converter
from modules.detection.converter import RuleError
from modules.detection import tester
from modules.detection.evaluator import EvaluationError

MAX_ATTEMPTS = 3
FENCE = "`" * 3
FENCE_RE = re.compile(
    re.escape(FENCE) + r"(?:ya?ml)?[ \t]*\n(.*?)" + re.escape(FENCE),
    re.DOTALL | re.IGNORECASE,
)

SYSTEM_PROMPT = r"""You are a detection engineer who writes Sigma rules (sigmahq.io).
Convert the user's description into exactly ONE valid Sigma rule.

Output rules:
- Reply with ONLY the YAML inside a yaml code fence. No explanations.
- Required fields: title, description, tags, logsource, detection, falsepositives, level.
- Do NOT write id, author, date or status. They are added automatically.
- level: one of informational, low, medium, high, critical.
- The description may be in Uzbek, Russian or English. Write the rule in English.
- Single-event detections only. Do NOT use count(), near, timeframe, aggregation or correlation.

Detection logic (very important):
- OR: list several values under ONE key. Never write the word "or" inside a value.
- AND: several keys inside one selection, or the modifier |contains|all.
- Combine named selections only in "condition" with and / or / not.
  The detection block MUST end with a "condition:" line.

Tags:
- Use the tactic tag and a CURRENT technique tag in lowercase, e.g. attack.persistence and attack.t1136.001.
- Never use deprecated IDs (for example T1086 is deprecated, use T1059.001).
- If you are not sure about the exact technique ID, use only the tactic tag.

Logsource:
- Process events: category: process_creation, product: windows.
- Windows Security/System event log (EventID based): product: windows and service: security (or system). Do NOT write a category for these. Never invent categories.

Fields:
- Use only real, well-known field names (Image, CommandLine, ParentImage, ParentCommandLine, EventID,
  TargetUserName, TargetFilename, DestinationIp, DestinationPort, User). Do not invent field names.
- Be precise about which EventID matches the description. If the description is vague, write the broadest
  correct rule and mention the limits in falsepositives.

Process creation fields (category: process_creation). Use ONLY these:
Image, CommandLine, ParentImage, ParentCommandLine, OriginalFileName, User, ParentUser,
IntegrityLevel, CurrentDirectory, Company, Product, Description, Hashes, ProcessId,
ParentProcessId, LogonId. There is NO TargetFileName in process events.
"X spawns Y" means ParentImage is X and Image is Y.

Example 0 (parent spawns child):

title: Office Application Spawning Shell
description: Detects Word or Excel starting cmd.exe or powershell.exe
tags:
  - attack.execution
  - attack.t1204.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Office macros used by legitimate business tools
level: high

Example 1:

title: Certutil Download Activity
description: Detects certutil used to download files from a URL
tags:
  - attack.command-and-control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\certutil.exe'
  selection_cli:
    CommandLine|contains:
      - 'urlcache'
      - '-split'
  condition: selection_img and selection_cli
falsepositives:
  - Rare administrative use
level: medium

Example 2 (OR written as a list):

title: Rundll32 or Regsvr32 Loading Remote Content
description: Detects rundll32 or regsvr32 with a URL on the command line
tags:
  - attack.defense-evasion
  - attack.t1218.010
  - attack.t1218.011
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\rundll32.exe'
      - '\regsvr32.exe'
  selection_url:
    CommandLine|contains:
      - 'http://'
      - 'https://'
  condition: selection_img and selection_url
falsepositives:
  - Software installers
level: medium
"""

YAML_HINT = (
    "Hint: express OR by listing the values under one key; never write the word 'or' inside a value. "
    "Quote strings that contain backslashes or special characters.\n"
)


class GenerationError(Exception):
    """AI to'g'ri Sigma qoidasi yoza olmadi."""


@dataclass
class Generated:
    yaml_text: str
    collection: object
    attempts: int
    warnings: list[str] = field(default_factory=list)
    report: object | None = None


OPEN_FENCE_RE = re.compile(re.escape(FENCE) + r"[ \t]*(?:ya?ml)?[ \t]*\n", re.IGNORECASE)


def extract_yaml(text: str) -> str:
    """Javobdan birinchi kod blokini oladi. Yopuvchi ``` bo'lmasa ham, blok bo'lmasa ham ishlaydi."""
    text = text.replace("\r\n", "\n")
    opening = OPEN_FENCE_RE.search(text)
    if not opening:
        return text.strip()
    body = text[opening.end():]
    closing = body.find(FENCE)
    return (body if closing == -1 else body[:closing]).strip()


def finalize(raw_yaml: str) -> tuple[str, list[str]]:
    """YAML'ni o'qiydi, id/author/date ni o'zimiz qo'yadi va qayta yozadi."""
    try:
        data = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as e:
        raise RuleError(f"YAML sintaksis xatosi: {e}") from e
    if not isinstance(data, dict):
        raise RuleError("Javob YAML qoida (key: value) emas")
    data["id"] = str(uuid.uuid4())
    data["author"] = "Qalqon"
    data["date"] = date.today().isoformat()
    data["status"] = "experimental"
    removed = converter.strip_unknown_techniques(data)
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True), removed


def validate(yaml_text: str):
    """Qoidani yuklaydi, mantiqiy tekshiruvlardan o'tkazadi va ikkala tilga o'giradi."""
    try:
        collection = converter.load(yaml_text)
        if len(collection.rules) != 1:
            raise RuleError("There must be exactly one rule")

        bad_ids = converter.unknown_techniques(collection)
        if bad_ids:
            raise RuleError(
                f"MITRE technique IDs not found or deprecated: {', '.join(bad_ids)}. "
                "Use current ATT&CK IDs, or only the tactic tag if unsure."
            )
        logsource_error = converter.bad_logsource(collection)
        if logsource_error:
            raise RuleError(logsource_error)
        field_error = converter.bad_fields(collection)
        if field_error:
            raise RuleError(field_error)

        for target in converter.BACKENDS:
            converter.convert(collection, target)
    except RuleError:
        raise
    except Exception as e:  # AI chiqargan g'alati YAML pySigma'da kutilmagan xato berishi mumkin
        raise RuleError(f"{type(e).__name__}: {e}") from e
    return collection


CONDITION_HINT = (
    "Hint: the detection block must contain a line like 'condition: selection' "
    "that names the selections to combine.\n"
)


def _hint(error: str) -> str:
    if error.startswith("YAML"):
        return YAML_HINT
    if "at least one condition" in error:
        return CONDITION_HINT
    return ""


def _test_feedback(report) -> str:
    lines = []
    for r in report.attacks:
        if not r.matched:
            lines.append(f"- MISSED attack event ({r.case.note}): {r.case.event}\n" + "\n".join(r.why))
    for r in report.benign:
        if r.matched:
            lines.append(f"- FALSE POSITIVE on benign event ({r.case.note}): {r.case.event}\n" + "\n".join(r.why))
    for f in report.missing_fields:
        lines.append(f"- Field '{f}' appears in none of the test events; use field names that exist in the events.")
    return "\n".join(lines)


def generate(
    description: str,
    provider: Provider | None = None,
    max_attempts: int = MAX_ATTEMPTS,
    on_retry: Callable[[int, str], None] | None = None,
    cases: list | None = None,
) -> Generated:
    provider = provider or get_provider()
    messages = [{"role": "user", "content": f"Detection description: {description}"}]
    last_error = ""

    for attempt in range(1, max_attempts + 1):
        reply = provider.chat(SYSTEM_PROMPT, messages, temperature=0.2)
        report, feedback = None, ""
        try:
            yaml_text, removed = finalize(extract_yaml(reply))
            collection = validate(yaml_text)
            if cases:
                try:
                    report = tester.run_tests(yaml_text, cases)
                except EvaluationError as e:
                    raise RuleError(
                        f"The rule uses features that cannot be tested: {e}. Use simple selections, "
                        "modifiers contains/startswith/endswith/all/re and and/or/not."
                    ) from e
                if report.verified and not report.ok:
                    last_error = (
                        f"log sinovi: hujum {report.hits}/{len(report.attacks)}, "
                        f"yolg'on signal {report.false_positives}/{len(report.benign)}"
                    )
                    feedback = _test_feedback(report)
        except RuleError as e:
            last_error = str(e)
            if on_retry:
                on_retry(attempt, last_error)
            messages += [
                {"role": "assistant", "content": reply},
                {
                    "role": "user",
                    "content": (
                        f"The rule failed validation: {last_error}\n{_hint(last_error)}"
                        "Fix it and reply again with the full corrected rule, YAML only."
                    ),
                },
            ]
            continue

        if feedback and attempt < max_attempts:
            if on_retry:
                on_retry(attempt, last_error)
            messages += [
                {"role": "assistant", "content": reply},
                {
                    "role": "user",
                    "content": (
                        "The rule is valid but failed testing against sample events:\n"
                        f"{feedback}\n"
                        "Fix the rule so it catches every attack event and none of the benign events. "
                        "Write a general rule, do not hard-code the events. "
                        "Reply with the full corrected rule, YAML only."
                    ),
                },
            ]
            continue

        warnings = []
        if removed:
            warnings.append(f"Noto'g'ri/eskirgan MITRE ID olib tashlandi: {', '.join(removed)}")
        if not converter.attack_techniques(collection):
            warnings.append("MITRE ATT&CK texnika tegi (attack.tXXXX) yo'q")
        if converter.mitre_attack_techniques is None:
            warnings.append("MITRE bazasi topilmadi, texnika ID'lari tekshirilmadi")
        return Generated(
            yaml_text=yaml_text, collection=collection, attempts=attempt, warnings=warnings, report=report
        )

    raise GenerationError(
        f"{max_attempts} urinishdan keyin ham to'g'ri qoida chiqmadi. Oxirgi xato: {last_error}"
    )
