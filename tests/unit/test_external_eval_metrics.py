"""X1 to X4, Wilson intervals and the cluster bootstrap (spec 062, protocol sections 6 and 7)."""

from __future__ import annotations

import pytest

from benchmarks.external_eval.metrics import (
    BOOTSTRAP_RESAMPLES,
    BOOTSTRAP_SEED,
    Z,
    cluster_bootstrap,
    confusion,
    proportion,
    x_metrics,
)

pytestmark = pytest.mark.unit


def test_constants_are_the_registered_values() -> None:
    assert Z == 1.959964
    assert BOOTSTRAP_RESAMPLES == 2000
    assert BOOTSTRAP_SEED == 20261009


def test_wilson_matches_a_known_interval() -> None:
    p = proportion(8, 10)
    assert p.estimate == pytest.approx(0.8)
    assert p.low == pytest.approx(0.4901625, abs=1e-6)
    assert p.high == pytest.approx(0.9433178, abs=1e-6)
    assert not p.undefined


def test_wilson_at_the_edges() -> None:
    zero, full = proportion(0, 5), proportion(5, 5)
    assert zero.low == 0.0
    assert zero.high == pytest.approx(0.4344825, abs=1e-6)
    assert full.high == pytest.approx(1.0)
    assert full.low == pytest.approx(0.5655175, abs=1e-6)


def test_zero_denominator_is_undefined_with_no_estimate() -> None:
    p = proportion(0, 0)
    assert p.undefined
    assert (p.k, p.n, p.estimate, p.low, p.high) == (0, 0, None, None, None)


def test_proportion_refuses_impossible_counts() -> None:
    with pytest.raises(ValueError):
        proportion(3, 2)
    with pytest.raises(ValueError):
        proportion(-1, 2)


def test_x_metrics_numerators_and_denominators() -> None:
    # (label, predicted): 3 tp, 1 fn, 2 fp, 4 tn
    pairs = [(True, True)] * 3 + [(True, False)] + [(False, True)] * 2 + [(False, False)] * 4
    c = confusion(pairs)
    assert (c.tp, c.fn, c.fp, c.tn) == (3, 1, 2, 4)
    m = x_metrics(c)
    assert (m["X1"].k, m["X1"].n) == (3, 4)
    assert (m["X2"].k, m["X2"].n) == (4, 6)
    assert (m["X3"].k, m["X3"].n) == (3, 5)
    assert (m["X4"].k, m["X4"].n) == (4, 10)


def test_a_predictor_that_never_fires_leaves_precision_undefined() -> None:
    m = x_metrics(confusion([(True, False), (False, False)]))
    assert m["X3"].undefined
    assert not m["X1"].undefined


def test_no_units_leaves_every_metric_undefined() -> None:
    assert all(p.undefined for p in x_metrics(confusion([])).values())


def test_bootstrap_is_deterministic_and_resamples_whole_clusters() -> None:
    units = [("a", True, True), ("a", True, True), ("b", False, False), ("c", True, False)]
    first = cluster_bootstrap(units, resamples=200)
    assert first == cluster_bootstrap(units, resamples=200)
    # X4 over whole clusters can only take values made of cluster prevalences.
    x4 = first["X4"]
    assert x4 is not None
    assert 0.0 <= x4[0] <= x4[1] <= 1.0


def test_bootstrap_of_a_single_cluster_is_its_own_value() -> None:
    units = [("only", True, True), ("only", False, True)]
    out = cluster_bootstrap(units, resamples=50)
    assert out["X4"] == (0.5, 0.5)
    assert out["X2"] == (0.0, 0.0)


def test_bootstrap_with_no_defined_resample_is_none() -> None:
    out = cluster_bootstrap([("a", False, False)], resamples=20)
    assert out["X1"] is None
    assert out["X3"] is None
