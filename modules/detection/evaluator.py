import fnmatch
import re
from collections.abc import Callable

Event = dict
Test = Callable[[Event], bool]

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re"}
TOKEN_RE = re.compile(r"(?:1|all)\s+of\s+[\w*]+|\(|\)|\w+", re.IGNORECASE)
QUANTIFIER_RE = re.compile(r"(1|all)\s+of\s+([\w*]+)", re.IGNORECASE)


class EvaluationError(Exception):
    """Qoidani sinash mumkin emas (qo'llanmaydigan imkoniyat yoki noto'g'ri tuzilma)."""


def _glob_to_regex(pattern: str) -> str:
    """Sigma wildcard: * va ?. Faqat \\* va \\? escape hisoblanadi, boshqa backslash oddiy belgi."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def _value_test(value, modifiers: list[str]) -> Callable[[object], bool]:
    if value is None:
        return lambda v: v is None or v == ""
    if "re" in modifiers:
        try:
            rx = re.compile(str(value))
        except re.error as e:
            raise EvaluationError(f"Noto'g'ri regex '{value}': {e}") from e
        return lambda v: v is not None and rx.search(str(v)) is not None

    body = _glob_to_regex(str(value))
    if "contains" in modifiers:
        body = ".*" + body + ".*"
    elif "startswith" in modifiers:
        body = body + ".*"
    elif "endswith" in modifiers:
        body = ".*" + body
    rx = re.compile(body, re.DOTALL | re.IGNORECASE)
    return lambda v: v is not None and rx.fullmatch(str(v)) is not None


def _get(event: Event, field: str):
    if field in event:
        return event[field]
    lowered = field.lower()
    for key, value in event.items():
        if str(key).lower() == lowered:
            return value
    return None


def _item_test(key: str, value) -> tuple[str, Test]:
    field, *modifiers = key.split("|")
    unsupported = [m for m in modifiers if m not in SUPPORTED_MODIFIERS]
    if unsupported:
        raise EvaluationError(f"Modifikator qo'llanmaydi: {', '.join(unsupported)} ({key})")
    values = value if isinstance(value, list) else [value]
    tests = [_value_test(v, modifiers) for v in values]
    combine = all if "all" in modifiers else any
    return field, lambda event: combine(t(_get(event, field)) for t in tests)


def _selection_test(selection, fields: set[str]) -> Test:
    if isinstance(selection, dict):
        parts = []
        for key, value in selection.items():
            field, test = _item_test(str(key), value)
            fields.add(field)
            parts.append(test)
        return lambda event: all(p(event) for p in parts)

    if isinstance(selection, list) and selection:
        if all(isinstance(x, dict) for x in selection):
            subs = [_selection_test(x, fields) for x in selection]
            return lambda event: any(s(event) for s in subs)
        if not any(isinstance(x, (dict, list)) for x in selection):
            # kalit so'zlar: istalgan maydonda uchrasa
            tests = [_value_test(x, ["contains"]) for x in selection]
            return lambda event: any(t(v) for t in tests for v in event.values())

    raise EvaluationError("Selection tuzilmasi qo'llanmaydi (dict, dict'lar ro'yxati yoki kalit so'zlar kerak)")


def _or(a: Test, b: Test) -> Test:
    return lambda event: a(event) or b(event)


def _and(a: Test, b: Test) -> Test:
    return lambda event: a(event) and b(event)


def _not(a: Test) -> Test:
    return lambda event: not a(event)


class _ConditionParser:
    """condition qatori: not > and > or, qavslar, '1 of sel_*', 'all of them'."""

    def __init__(self, tokens: list[str], selections: dict[str, Test]):
        self.tokens, self.selections, self.pos = tokens, selections, 0

    def _peek(self) -> str:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else ""

    def _take(self) -> str:
        if self.pos >= len(self.tokens):
            raise EvaluationError("Condition tugamagan (kutilmagan oxir)")
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self) -> Test:
        node = self._or()
        if self.pos != len(self.tokens):
            raise EvaluationError(f"Condition o'qib bo'lmadi: '{self.tokens[self.pos]}' joyida")
        return node

    def _or(self) -> Test:
        left = self._and()
        while self._peek() == "or":
            self._take()
            left = _or(left, self._and())
        return left

    def _and(self) -> Test:
        left = self._not()
        while self._peek() == "and":
            self._take()
            left = _and(left, self._not())
        return left

    def _not(self) -> Test:
        if self._peek() == "not":
            self._take()
            return _not(self._not())
        return self._atom()

    def _atom(self) -> Test:
        token = self._take()
        if token == "(":
            node = self._or()
            if self._take() != ")":
                raise EvaluationError("Qavs yopilmagan")
            return node

        quantifier = QUANTIFIER_RE.fullmatch(token)
        if quantifier:
            mode, target = quantifier.group(1).lower(), quantifier.group(2)
            names = (
                list(self.selections)
                if target.lower() == "them"
                else [n for n in self.selections if fnmatch.fnmatchcase(n, target)]
            )
            if not names:
                raise EvaluationError(f"'{token}' hech bir selection'ga mos kelmadi")
            tests = [self.selections[n] for n in names]
            combine = all if mode == "all" else any
            return lambda event: combine(t(event) for t in tests)

        if token not in self.selections:
            raise EvaluationError(f"Condition'da noma'lum selection: '{token}'")
        return self.selections[token]


class Matcher:
    """Sigma qoidasi (lug'at ko'rinishida) bitta voqeaga mos keladimi."""

    def __init__(self, rule: dict):
        detection = rule.get("detection")
        if not isinstance(detection, dict):
            raise EvaluationError("Qoidada 'detection' bo'limi yo'q")
        if "timeframe" in detection:
            raise EvaluationError("timeframe/aggregation qoidalari qo'llanmaydi")

        self.fields: set[str] = set()
        selections = {
            str(name): _selection_test(sel, self.fields)
            for name, sel in detection.items()
            if name not in ("condition", "timeframe")
        }

        conditions = detection.get("condition")
        conditions = conditions if isinstance(conditions, list) else [conditions]
        self._tests: list[Test] = []
        for cond in conditions:
            if not isinstance(cond, str) or not cond.strip():
                raise EvaluationError("Condition yo'q yoki matn emas")
            if TOKEN_RE.sub("", cond).strip():
                raise EvaluationError(f"Condition qo'llanmaydi (aggregation?): {cond}")
            self._tests.append(_ConditionParser(TOKEN_RE.findall(cond), selections).parse())

    def matches(self, event: Event) -> bool:
        return any(test(event) for test in self._tests)
