import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from generate_report import render_cross_domain_summary


def test_cross_domain_summary_is_concise_and_guarded():
    html = render_cross_domain_summary({"discovery": {"cross_domain_insights": [{"title":"Identity + Security","domains":["Identity & Access","Security"],"priority":"P1","coverage_guardrail":"Validar cobertura antes de remediar."}]}})
    assert "Identity + Security" in html
    assert "não alteram o score" in html
    assert "Validar cobertura" in html


def test_cross_domain_summary_explains_absence_without_claiming_compliance():
    html = render_cross_domain_summary({"discovery": {}})
    assert "Nenhuma correlação" in html
    assert "conform" not in html.lower()
