import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import collect_graph


def test_graph_latency_defaults_are_bounded(monkeypatch):
    monkeypatch.delenv("ASSESSMENT_GRAPH_REQUEST_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("ASSESSMENT_SIGNIN_MAX_PAGES", raising=False)
    assert collect_graph.bounded_env_int("ASSESSMENT_GRAPH_REQUEST_TIMEOUT_SECONDS", 30, 5, 300) == 30
    assert collect_graph.bounded_env_int("ASSESSMENT_SIGNIN_MAX_PAGES", 10, 0, 10000) == 10


def test_graph_latency_limits_remain_operator_overridable(monkeypatch):
    monkeypatch.setenv("ASSESSMENT_GRAPH_REQUEST_TIMEOUT_SECONDS", "90")
    monkeypatch.setenv("ASSESSMENT_SIGNIN_MAX_PAGES", "25")
    assert collect_graph.bounded_env_int("ASSESSMENT_GRAPH_REQUEST_TIMEOUT_SECONDS", 30, 5, 300) == 90
    assert collect_graph.bounded_env_int("ASSESSMENT_SIGNIN_MAX_PAGES", 10, 0, 10000) == 25
