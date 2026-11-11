"""Quality metrics for Smart Connect: no background speed-test traffic.

Endpoint measurements are not the same as end-to-end VPN RTT. Missing metrics
remain unknown instead of being made up. A conservative hysteresis prevents
flapping between servers with similar scores.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from statistics import median
from typing import Any

MAX_SAMPLES = 24


@dataclass(frozen=True)
class Quality:
    score: float
    reliability: float
    latency_ms: float | None
    jitter_ms: float | None
    samples: int


class QualityTracker:
    def __init__(self, stored: dict[str, Any] | None = None) -> None:
        self._history: dict[str, deque[int | None]] = {}
        if not isinstance(stored, dict):
            stored = {}
        for key, values in stored.items():
            if not isinstance(key, str) or not isinstance(values, list):
                continue
            clean = [v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 120000
                     else None for v in values[-MAX_SAMPLES:]]
            self._history[key] = deque(clean, maxlen=MAX_SAMPLES)

    def record(self, profile_id: str, milliseconds: int | None) -> None:
        if not profile_id:
            return
        value = milliseconds if isinstance(milliseconds, int) and 0 <= milliseconds <= 120000 else None
        self._history.setdefault(profile_id, deque(maxlen=MAX_SAMPLES)).append(value)

    def quality(self, profile_id: str) -> Quality | None:
        samples = list(self._history.get(profile_id, ()))
        if not samples:
            return None
        successes = [v for v in samples if v is not None]
        reliability = len(successes) / len(samples)
        if not successes:
            return Quality(0., reliability, None, None, len(samples))
        typical = float(median(successes))
        # Median successive absolute differences; reflects observed endpoint RTT variation.
        pairs = [(a, b) for a, b in zip(samples, samples[1:]) if a is not None and b is not None]
        jitter = float(median([abs(a - b) for a, b in pairs])) if pairs else None
        latency_score = 100 / (1 + typical / 180)
        stability_score = 100 / (1 + (jitter or 0) / 70)
        score = 0.50 * latency_score + 0.35 * reliability * 100 + 0.15 * stability_score
        # Low history confidence: reduce influence of the first one/two measurements.
        confidence = min(1.0, len(samples) / 4.0)
        score = score * confidence + (50.0 * confidence * (1 - confidence))
        return Quality(round(score, 1), reliability, typical, jitter, len(samples))

    def best(self, ids: list[str], valid_latency: list[int | None]) -> int | None:
        candidates: list[tuple[float, int]] = []
        for i, key in enumerate(ids):
            if i >= len(valid_latency) or valid_latency[i] is None:
                continue
            quality = self.quality(key)
            # If history is absent, still allow choosing an available node by RTT.
            score = quality.score if quality else 100 / (1 + valid_latency[i] / 180)
            candidates.append((score, i))
        return max(candidates, default=(0, None), key=lambda item: item[0])[1]

    def dump(self) -> dict[str, list[int | None]]:
        return {key: list(values) for key, values in self._history.items() if values}


def should_switch(current: Quality | None, candidate: Quality | None, *,
                  current_latency: int | None, candidate_latency: int | None,
                  margin: float = 14.0) -> bool:
    """Only switch on meaningful sustained improvement; caller enforces cooldown."""
    if candidate_latency is None:
        return False
    if current_latency is None:
        return bool(candidate and candidate.reliability >= 0.5 and candidate.samples >= 2)
    if not current or not candidate:
        return candidate_latency + 150 < current_latency
    return (candidate.samples >= 3 and candidate.reliability >= 0.65
            and candidate.score >= current.score + margin)
