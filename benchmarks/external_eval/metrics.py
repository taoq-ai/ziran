"""X1 to X4 with Wilson intervals, and the cluster bootstrap (protocol sections 6 and 7)."""

from __future__ import annotations

import math
import random
import statistics
from collections import defaultdict
from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

#: Two-sided 95% normal quantile, as in preregistration.md section 5.1.
Z = 1.959964
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20261009
METRICS = ("X1", "X2", "X3", "X4")


class Proportion(BaseModel):
    k: int
    n: int
    estimate: float | None
    low: float | None
    high: float | None
    undefined: bool


class Confusion(BaseModel):
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0


def proportion(k: int, n: int) -> Proportion:
    """k of n with a Wilson score interval; n = 0 is undefined, with no estimate."""
    if n < 0 or k < 0 or k > n:
        raise ValueError(f"impossible proportion {k}/{n}")
    if n == 0:
        return Proportion(k=0, n=0, estimate=None, low=None, high=None, undefined=True)
    p = k / n
    z2 = Z * Z
    centre = (p + z2 / (2 * n)) / (1 + z2 / n)
    half = Z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / (1 + z2 / n)
    return Proportion(
        k=k, n=n, estimate=p, low=max(0.0, centre - half), high=min(1.0, centre + half),
        undefined=False,
    )  # fmt: skip


def confusion(pairs: Iterable[tuple[bool, bool]]) -> Confusion:
    """Confusion matrix from (label positive, predictor calls success) pairs."""
    c = Confusion()
    for label, predicted in pairs:
        if label and predicted:
            c.tp += 1
        elif label:
            c.fn += 1
        elif predicted:
            c.fp += 1
        else:
            c.tn += 1
    return c


def _counts(c: Confusion) -> dict[str, tuple[int, int]]:
    return {
        "X1": (c.tp, c.tp + c.fn),
        "X2": (c.tn, c.tn + c.fp),
        "X3": (c.tp, c.tp + c.fp),
        "X4": (c.tp + c.fn, c.tp + c.fn + c.fp + c.tn),
    }


def x_metrics(c: Confusion) -> dict[str, Proportion]:
    """Sensitivity, specificity, precision and label prevalence (protocol section 6)."""
    return {name: proportion(k, n) for name, (k, n) in _counts(c).items()}


def cluster_bootstrap(
    units: Sequence[tuple[str, bool, bool]],
    resamples: int = BOOTSTRAP_RESAMPLES,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, tuple[float, float] | None]:
    """Percentile 95% interval per metric, resampling whole clusters.

    ``units`` are (cluster, label, predicted). A resample whose denominator is zero gives no
    value for that metric; a metric with no value in any resample is None.
    """
    by_cluster: dict[str, list[tuple[bool, bool]]] = defaultdict(list)
    for cluster, label, predicted in units:
        by_cluster[cluster].append((label, predicted))
    clusters = sorted(by_cluster)
    values: dict[str, list[float]] = {m: [] for m in METRICS}
    rng = random.Random(seed)
    for _ in range(resamples if clusters else 0):
        drawn = rng.choices(clusters, k=len(clusters))
        counts = _counts(confusion(pair for c in drawn for pair in by_cluster[c]))
        for name, (k, n) in counts.items():
            if n:
                values[name].append(k / n)
    out: dict[str, tuple[float, float] | None] = {}
    for name, vals in values.items():
        if not vals:
            out[name] = None
        elif len(set(vals)) == 1:
            out[name] = (vals[0], vals[0])
        else:
            cuts = statistics.quantiles(vals, n=40, method="inclusive")
            out[name] = (cuts[0], cuts[-1])
    return out
