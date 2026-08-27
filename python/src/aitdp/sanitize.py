"""Helpers to neutralise flagged content based on evidence spans."""

from __future__ import annotations

import re

from .models import ThreatEvent

_INVISIBLE = re.compile(
    r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069\U000E0000-\U000E007F]"
)


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi-override and Unicode tag characters."""
    return _INVISIBLE.sub("", text)


def redact_spans(
    text: str, events: list[ThreatEvent], placeholder: str = "[REDACTED:{category}]"
) -> str:
    """Replace every evidence span from ``events`` with a placeholder.

    Spans are applied from the end of the string backwards so offsets stay valid.
    """
    spans: list[tuple[int, int, str]] = []
    for ev in events:
        for e in ev.evidence:
            if e.start is not None and e.end is not None and e.end > e.start:
                spans.append((e.start, e.end, ev.category.value))
    if not spans:
        return text
    spans.sort(key=lambda s: s[0])
    merged: list[tuple[int, int, str]] = []
    for s, e, c in spans:
        if merged and s <= merged[-1][1]:
            ps, pe, pc = merged[-1]
            merged[-1] = (ps, max(pe, e), pc)
        else:
            merged.append((s, e, c))
    out = text
    for s, e, c in reversed(merged):
        out = out[:s] + placeholder.format(category=c) + out[e:]
    return out


__all__ = ["redact_spans", "strip_invisible"]
