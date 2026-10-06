import importlib.util
import re
import sys

import joblib
import pytest

from trustgate.config import PROJECT_ROOT
from trustgate.ml import MLClassifier
from trustgate.ml.dataset import Example, deduplicate, preprocess
from trustgate.ml.train import binary_metrics, build_pipeline
from trustgate.rules import lexicons as lx


def _load_run_eval():
    spec = importlib.util.spec_from_file_location("run_eval", PROJECT_ROOT / "eval" / "run_eval.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


SPAM = [
    "WINNER! claim your free prize now, call to claim cash reward",
    "Urgent! you have won a free cash prize, claim now",
    "Free entry to win cash prize, text WIN to claim",
    "Claim your free reward now, winner selected for cash",
    "Congratulations winner, free prize claim today",
    "You won cash, claim free prize reward now",
] * 3
HAM = [
    "are we still meeting for lunch tomorrow",
    "can you pick up milk on the way home",
    "see you at the meeting tomorrow afternoon",
    "thanks for dinner last night, it was lovely",
    "running late, see you at home soon",
    "lunch tomorrow at the usual place?",
] * 3


@pytest.fixture(scope="module")
def toy_model_path(tmp_path_factory):
    texts = SPAM + HAM
    labels = [1] * len(SPAM) + [0] * len(HAM)
    pipe = build_pipeline(c=4.0).fit(texts, labels)
    path = tmp_path_factory.mktemp("model") / "toy.joblib"
    joblib.dump({"pipeline": pipe, "meta": {"model": "toy"}}, path)
    return path


def test_preprocess_replaces_volatile_tokens():
    out = preprocess("Call +44 7700 900123 or visit https://x.example/a, pay £45.00 to a@b.com by 2026")
    assert "phonetoken" in out and "urltoken" in out and "moneytoken" in out and "emailtoken" in out
    assert not re.search(r"[1-9]", out)
    assert preprocess("re : 6 . hello , world") == "re: 0. hello, world"


def test_deduplicate_drops_duplicates_and_conflicts():
    examples = [
        Example("Free prize!", 1, "sms"), Example("free   PRIZE!", 1, "sms"),
        Example("hello there", 0, "sms"), Example("Hello there", 1, "email"),
        Example("unique", 0, "sms"),
    ]
    kept, dropped = deduplicate(examples)
    assert [e.text for e in kept] == ["Free prize!", "unique"]
    assert dropped == 3


def test_classifier_roundtrip_and_explanations(toy_model_path):
    clf = MLClassifier.load(toy_model_path)
    assert clf is not None and clf.meta["model"] == "toy"
    spam = clf.predict("Claim your free cash prize now, winner!")
    ham = clf.predict("see you at lunch tomorrow")
    assert spam.probability > 0.5 > ham.probability
    assert 0 <= ham.score <= 100
    assert spam.top_terms and all(isinstance(t, str) for t in spam.top_terms)


def test_missing_or_corrupt_model_disables_layer(tmp_path):
    assert MLClassifier.load(tmp_path / "nope.joblib") is None
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"not a model")
    assert MLClassifier.load(bad) is None


def test_binary_metrics():
    m = binary_metrics([1, 1, 0, 0], [1, 0, 1, 0], [0.9, 0.4, 0.6, 0.1])
    assert m["confusion_matrix"] == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}
    assert m["precision"] == m["recall"] == m["f1"] == 0.5
    assert m["roc_auc"] == 0.75


# ------------------------------------------------------------------ evaluation set


def test_scenarios_are_valid_and_balanced():
    run_eval = _load_run_eval()
    scenarios = run_eval.load_scenarios()
    ids = [s.id for s in scenarios]
    assert len(ids) == len(set(ids))
    assert sum(s.is_scam for s in scenarios) >= 18
    assert sum(not s.is_scam for s in scenarios) >= 9


def test_scenarios_use_fictional_brands_only():
    run_eval = _load_run_eval()
    real = [re.compile(rf"\b{re.escape(b.name)}\b", re.IGNORECASE) for b in lx.BRANDS]
    for s in run_eval.load_scenarios():
        text = s.request.model_dump_json()
        hits = [p.pattern for p in real if p.search(text)]
        assert not hits, (s.id, hits)


def test_eval_metrics():
    run_eval = _load_run_eval()
    scenarios = run_eval.load_scenarios()[:4]
    outcomes = [run_eval.Outcome(score=90, flagged=True, scam_type=s.scam_type) for s in scenarios]
    m = run_eval.metrics(scenarios, outcomes)
    assert m["recall"] == 1.0 and m["scam_type_accuracy"] == 1.0
