"""Evaluate the default pipeline on a labelled JSONL dataset."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python" / "src"))

from aitdp import Pipeline  # noqa: E402

HERE = Path(__file__).resolve().parent


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(HERE / "data" / "seed.jsonl"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high", "critical"])
    ap.add_argument("--show-misses", action="store_true")
    args = ap.parse_args()

    from aitdp import Severity

    threshold = Severity(args.min_severity)
    pipeline = Pipeline.default()
    rows = [json.loads(l) for l in Path(args.data).read_text(encoding="utf-8").splitlines() if l.strip()]

    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    misses = []
    total_ms = 0.0
    for row in rows:
        r = pipeline.scan(row["text"], row.get("stage", "user_input"))
        total_ms += r.duration_ms
        detected = r.max_severity is not None and r.max_severity >= threshold
        truth = row["label"] == "malicious"
        key = row.get("stage", "user_input")
        for k in (key, "_all"):
            if detected and truth:
                stats[k]["tp"] += 1
            elif detected and not truth:
                stats[k]["fp"] += 1
            elif not detected and truth:
                stats[k]["fn"] += 1
            else:
                stats[k]["tn"] += 1
        if detected != truth:
            misses.append({"text": row["text"], "label": row["label"], "got": r.summary()})

    out = {}
    for k, s in sorted(stats.items()):
        p, r_, f = prf(s["tp"], s["fp"], s["fn"])
        out[k] = {**s, "precision": round(p, 3), "recall": round(r_, 3), "f1": round(f, 3)}
    out["_meta"] = {"samples": len(rows), "avg_ms": round(total_ms / max(1, len(rows)), 3)}

    if args.json:
        print(json.dumps(out, indent=2))
        return 0
    print(f"{'stage':<20}{'n':>5}{'P':>8}{'R':>8}{'F1':>8}")
    for k, s in out.items():
        if k == "_meta":
            continue
        n = s["tp"] + s["fp"] + s["fn"] + s["tn"]
        print(f"{k:<20}{n:>5}{s['precision']:>8.3f}{s['recall']:>8.3f}{s['f1']:>8.3f}")
    print(f"\n{len(rows)} samples · {out['_meta']['avg_ms']} ms/sample avg")
    if args.show_misses and misses:
        print("\nMisclassified:")
        for m in misses:
            print(f"  [{m['label']}] {m['text'][:80]!r} -> {m['got']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
