"""Modelo interno de maturidade, transparente e independente de benchmark externo."""
from __future__ import annotations

LEVELS=((20,"Inicial"),(40,"Reativo"),(60,"Definido"),(80,"Gerenciado"),(100,"Otimizado"))

def build(data: dict) -> dict:
    score=data.get("score",{}).get("overall")
    coverage=data.get("metadata",{}).get("coverage")
    if not isinstance(score,(int,float)):
        score=data.get("overall_score")
    if not isinstance(coverage,(int,float)):
        coverage=None
    level="Não determinado"
    if isinstance(score,(int,float)):
        level=next((name for ceiling,name in LEVELS if score <= ceiling),"Otimizado")
    confidence="alta" if coverage is not None and coverage>=80 else "média" if coverage is not None and coverage>=60 else "baixa"
    return {
        "model":"Assessment Engine Internal Maturity Model",
        "maturity_level":level,
        "assessment_score":score,
        "coverage":coverage,
        "confidence":confidence,
        "methodology":"Faixas internas fixas sobre o score determinístico; cobertura é exibida separadamente e reduz a confiança interpretativa quando limitada.",
        "external_benchmark":{"status":"unavailable","reason":"Nenhuma coorte externa validada e metodologia comparável foi fornecida; percentis de mercado não são inferidos."},
        "guardrails":["Maturidade interna não equivale a conformidade.","Cobertura limitada não deve ser tratada como postura madura.","Benchmark externo só pode ser publicado com coorte real, metodologia documentada e comparabilidade validada."],
    }
