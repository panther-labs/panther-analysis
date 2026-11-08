import re
from collections.abc import Mapping, Sequence

# Phrases that tell a model to drop its instructions, reveal them, or send local secrets out.
# Each pattern was chosen to be explicit enough that ordinary prompts do not use it.
INJECTION_PATTERNS = {
    "instruction override": re.compile(
        r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(of\s+)?(the\s+|your\s+)?"
        r"(previous|prior|above|earlier|preceding|original)\s+"
        r"(instructions|prompts|rules|directives|guidelines)\b",
        re.IGNORECASE,
    ),
    "system prompt extraction": re.compile(
        r"\b(reveal|print|repeat|output|show|dump)\s+(me\s+)?(your|the)\s+"
        r"(full\s+|entire\s+|exact\s+)?"
        r"(system\s+prompt|initial\s+instructions|hidden\s+instructions)\b",
        re.IGNORECASE,
    ),
    "credential exfiltration": re.compile(
        r"\b(send|post|upload|exfiltrate|forward)\b[^\n]{0,120}"
        r"(~/\.ssh/id_[a-z0-9]+|\.aws/credentials|\.env\b)"
        r"[^\n]{0,120}\b(https?://|webhook)",
        re.IGNORECASE,
    ),
}

MAX_TEXT = 200_000


def _texts(value):
    """Yield every string in the request body except the system prompt.

    Defensive system prompts ("never reveal your system prompt") would match on every request.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in (v for k, v in value.items() if k != "system"):
            yield from _texts(item)
    elif isinstance(value, Sequence):
        for item in value:
            yield from _texts(item)


def _match(event):
    body = event.deep_get("input", "inputBodyJson", default={})
    texts = [text[:MAX_TEXT] for text in _texts(body)]
    for name, pattern in INJECTION_PATTERNS.items():
        if any(pattern.search(text) for text in texts):
            return name
    return None


def rule(event):
    if event.get("operation") not in ("InvokeModel", "Converse"):
        return False
    return _match(event) is not None


def title(event):
    return (
        f"Possible prompt injection ({_match(event)}) in a request to "
        f"[{event.get('modelId', '<UNKNOWN MODEL>')}] by "
        f"[{event.deep_get('identity', 'arn', default='<UNKNOWN IDENTITY>')}]"
    )


def alert_context(event):
    return {
        "modelId": event.get("modelId"),
        "operation": event.get("operation"),
        "requestId": event.get("requestId"),
        "identity": event.deep_get("identity", "arn"),
        "pattern": _match(event),
    }
