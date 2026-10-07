from lifecycle_finops import build


def test_finops_deduplicates_only_explicit_same_key():
    discovery = {"advisor_recommendations": [
        {"id": "same", "annual_savings": 100, "currency": "BRL"},
        {"id": "same", "annual_savings": 80, "currency": "BRL"},
        {"annual_savings": 50, "currency": "BRL"},
    ]}
    result = build(discovery)
    assert result["savings"]["upper_bound"] == 230.0
    assert result["savings"]["deduplicated_upper_bound"] == 150.0
    assert result["savings"]["raw_signal_count"] == 3
    assert result["savings"]["deduplicated_signal_count"] == 2
    assert result["savings"]["realizable_savings"] is None


def test_finops_does_not_merge_distinct_recommendations():
    result = build({"advisor_recommendations": [{"id": "a", "savings": 10}, {"id": "b", "savings": 20}]})
    assert result["savings"]["deduplicated_upper_bound"] == 30.0
