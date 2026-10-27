"""Combine local signals and optional model text without pretending to prove safety."""
import re


def _risk_rank(value):
    return {"Low": 0, "Medium": 1, "High": 2, "Inconclusive": -1}.get(value, -1)


def combine_assessment(rule_result, url_result=None, ai_result=None):
    candidates = [rule_result.get("risk_level", "Inconclusive")]
    if url_result:
        candidates.append(url_result.get("risk_level", "Inconclusive"))
    risk = max(candidates, key=_risk_rank)
    indicators = list(rule_result.get("indicators", []))
    if url_result:
        indicators.extend(url_result.get("indicators", []))
    explanation_parts = [rule_result.get("explanation", "")]
    if url_result:
        explanation_parts.append("URL check: " + url_result.get("explanation", ""))
    result = {
        "risk_level": risk,
        "category": rule_result.get("category", "Security review"),
        "indicators": list(dict.fromkeys(indicators)),
        "explanation": " ".join(part for part in explanation_parts if part),
        "recommended_actions": rule_result.get("recommended_actions", []),
        "ai_analysis": ai_result or None,
        "disclaimer": "This is an educational triage tool, not a security scanner or a guarantee. False positives and false negatives are possible."
    }
    if ai_result:
        match = re.search(r"Risk level\s*:\s*(Low|Medium|High|Inconclusive)", ai_result, re.I)
        if match:
            ai_risk = match.group(1).capitalize()
            if _risk_rank(ai_risk) > _risk_rank(result["risk_level"]):
                result["risk_level"] = ai_risk
        result["explanation"] += " Gemma 4 analysis is included below; review its evidence critically."
    return result
