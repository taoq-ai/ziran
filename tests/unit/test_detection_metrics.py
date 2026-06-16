"""Unit tests for detection-accuracy metric math (spec 021, US1)."""

from __future__ import annotations

import pytest

from benchmarks.detection_accuracy import ConfusionMatrix, _metrics, _prf

pytestmark = pytest.mark.unit


def test_perfect_classifier() -> None:
    cm = ConfusionMatrix(tp=10, fp=0, fn=0, tn=10)
    p, r, f1 = _prf(cm)
    assert (p, r, f1) == (1.0, 1.0, 1.0)


def test_precision_recall_tradeoff() -> None:
    # 8 caught, 2 missed, 4 false alarms.
    cm = ConfusionMatrix(tp=8, fp=4, fn=2, tn=6)
    p, r, f1 = _prf(cm)
    assert p == round(8 / 12, 4)
    assert r == round(8 / 10, 4)
    assert f1 == round(2 * p * r / (p + r), 4)


def test_no_positive_predictions_zero_precision() -> None:
    cm = ConfusionMatrix(tp=0, fp=0, fn=5, tn=5)
    p, r, f1 = _prf(cm)
    assert p == 0.0
    assert r == 0.0
    assert f1 == 0.0


def test_class_imbalance_visible_in_confusion() -> None:
    # 1 positive among 99 negatives, caught — recall 1.0 but tiny support.
    cm = ConfusionMatrix(tp=1, fp=0, fn=0, tn=99)
    m = _metrics(cm, applicable=100)
    assert m.recall == 1.0
    # Wilson CI on a single positive is wide — lower bound well below 1.0.
    assert m.recall_ci[0] < 1.0


def test_add_routes_to_correct_cell() -> None:
    cm = ConfusionMatrix()
    cm.add(expected=True, actual=True)
    cm.add(expected=False, actual=True)
    cm.add(expected=True, actual=False)
    cm.add(expected=False, actual=False)
    assert (cm.tp, cm.fp, cm.fn, cm.tn) == (1, 1, 1, 1)
    assert cm.total == 4
