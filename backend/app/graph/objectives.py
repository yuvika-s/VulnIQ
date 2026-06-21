"""
Attacker objectives — the layer that turns finding-correlation into
attacker-objective attack-path analysis.

Attackers don't think in findings, they think in goals: "get production AWS",
"execute unauthorized trades", "read customer PII". Each finding is mapped to
the attacker objective(s) it advances, derived deterministically from the
capability it grants × the nature of the asset it sits on (data classification,
business function, repo/component name). Chains are then scored by how
effectively they reach a crown-jewel objective.
"""
from __future__ import annotations

from app.models import Capability

# --- objective catalogue --------------------------------------------------- #
# weight = crown-jewel value (0-1); cats = reachability categories the objective
# satisfies (used by the objective-reachability score).
CUSTOMER_DATA_ACCESS = "customer_data_access"
UNAUTHORIZED_TRADING = "unauthorized_trading"
FINANCIAL_RECORD_MODIFICATION = "financial_record_modification"
PAYMENT_SYSTEMS_ACCESS = "payment_systems_access"
PRODUCTION_AWS_ACCESS = "production_aws_access"
PRIVILEGED_CLOUD_ACCESS = "privileged_cloud_access"
ADMINISTRATIVE_CONTROL = "administrative_control"
CREDENTIAL_COMPROMISE = "credential_compromise"

OBJECTIVE_META: dict[str, dict] = {
    UNAUTHORIZED_TRADING:           {"label": "Execute unauthorized trades",       "weight": 1.00, "cats": {"trading", "crown"}},
    FINANCIAL_RECORD_MODIFICATION:  {"label": "Modify financial records",          "weight": 1.00, "cats": {"financial", "crown"}},
    PAYMENT_SYSTEMS_ACCESS:         {"label": "Access payment systems",            "weight": 0.98, "cats": {"payment", "crown"}},
    PRODUCTION_AWS_ACCESS:          {"label": "Gain production AWS control",        "weight": 0.95, "cats": {"production", "cloud", "crown"}},
    CUSTOMER_DATA_ACCESS:           {"label": "Access customer PII",               "weight": 0.90, "cats": {"customer_data", "crown"}},
    PRIVILEGED_CLOUD_ACCESS:        {"label": "Gain privileged cloud access",      "weight": 0.88, "cats": {"cloud", "production"}},
    ADMINISTRATIVE_CONTROL:         {"label": "Administrative control of app",     "weight": 0.85, "cats": {"admin", "crown"}},
    CREDENTIAL_COMPROMISE:          {"label": "Compromise credentials",            "weight": 0.55, "cats": {"credential"}},
}

# keyword -> domain tag. Matched against asset (classification/business/name/id)
# and finding (component/title/location) text.
_DOMAIN_KEYWORDS = {
    "cloud":        ("aws", "terraform", " iam", "iam ", "s3", "ec2", "lambda", "cloudfront",
                     "databricks", "gcs", "cloudwatch", "eks", "rds", "vpc", "cloud", "infra"),
    "trading":      ("trad", "trade", "order", "nest", "spark", "omnesys", "oms", "margin",
                     "rms", "exchange", "nse", "bse", "broking", "alpha", "infinitrade"),
    "payment":      ("payment", "withdraw", "funds", "settlement", "wallet", "payout", "gateway", "upi"),
    "financial":    ("ledger", "ledger", "finance", "financial", "accounting", "finone", "lending", "loan"),
    "customer_data":("kyc", "pan", "aadhaar", "pii", "customer", "personal", "profile", "ckyc",
                     "pmla", "onboarding", "credit", "score", "nbu", "registration"),
    "admin":        ("admin", "adminui", "console", "management", "back-office", "back office",
                     "bo portal", "portal", "superset", "dashboard"),
}

# impactful capabilities (a foothold-only capability advances no objective alone)
_IMPACT_CAPS = {
    Capability.DATA_READ, Capability.DATA_WRITE, Capability.CREDENTIAL_ACCESS,
    Capability.PRIV_ESCALATION, Capability.CODE_EXECUTION, Capability.FUNDS_ACCESS,
}


def _asset_text(asset) -> str:
    if not asset:
        return ""
    return " ".join(str(x).lower() for x in (
        getattr(asset, "asset_id", ""), getattr(asset, "name", ""),
        getattr(asset, "data_classification", ""), getattr(asset, "business_function", "")))


def _domains(finding, asset) -> set[str]:
    text = _asset_text(asset) + " " + " ".join(str(x).lower() for x in (
        getattr(finding, "component", ""), getattr(finding, "title", ""),
        getattr(finding, "location", ""), getattr(finding, "affected_asset_id", "")))
    return {dom for dom, kws in _DOMAIN_KEYWORDS.items() if any(k in text for k in kws)}


def objectives_for(finding, asset) -> list[str]:
    """Attacker objectives this finding advances, from capability × asset domain."""
    caps = set(getattr(finding, "grants", []) or [])
    if not caps:
        return []
    doms = _domains(finding, asset)
    crown = bool(asset and getattr(asset, "is_crown_jewel", False))
    objs: set[str] = set()

    cred_or_priv = caps & {Capability.CREDENTIAL_ACCESS, Capability.PRIV_ESCALATION, Capability.CODE_EXECUTION}
    write_or_funds = caps & {Capability.DATA_WRITE, Capability.FUNDS_ACCESS}

    if "cloud" in doms and cred_or_priv:
        objs.add(PRODUCTION_AWS_ACCESS)
        objs.add(PRIVILEGED_CLOUD_ACCESS)
    if "trading" in doms and (write_or_funds or Capability.CODE_EXECUTION in caps):
        objs.add(UNAUTHORIZED_TRADING)
    if "payment" in doms and (write_or_funds or caps & {Capability.DATA_READ, Capability.CREDENTIAL_ACCESS}):
        objs.add(PAYMENT_SYSTEMS_ACCESS)
    if "financial" in doms and (write_or_funds or Capability.DATA_WRITE in caps):
        objs.add(FINANCIAL_RECORD_MODIFICATION)
    if "customer_data" in doms and caps & {Capability.DATA_READ, Capability.CREDENTIAL_ACCESS}:
        objs.add(CUSTOMER_DATA_ACCESS)
    if "admin" in doms and caps & {Capability.INITIAL_ACCESS, Capability.PRIV_ESCALATION,
                                   Capability.CODE_EXECUTION, Capability.DATA_WRITE}:
        objs.add(ADMINISTRATIVE_CONTROL)
    if Capability.CREDENTIAL_ACCESS in caps:
        objs.add(CREDENTIAL_COMPROMISE)

    # Fallback: an impactful capability on a crown jewel with no specific domain
    # still represents control of a critical app / its data.
    if not objs and crown and (caps & _IMPACT_CAPS):
        dc = (getattr(asset, "data_classification", "") or "").lower()
        if any(k in dc for k in ("pii", "customer", "pan", "aadhaar", "kyc")):
            objs.add(CUSTOMER_DATA_ACCESS)
        else:
            objs.add(ADMINISTRATIVE_CONTROL)
    return sorted(objs, key=lambda o: -OBJECTIVE_META[o]["weight"])


def objective_label(obj: str) -> str:
    return OBJECTIVE_META.get(obj, {}).get("label", obj.replace("_", " "))


def objective_weight(obj: str) -> float:
    return OBJECTIVE_META.get(obj, {}).get("weight", 0.5)


def categories_of(objs) -> set[str]:
    cats: set[str] = set()
    for o in objs:
        cats |= OBJECTIVE_META.get(o, {}).get("cats", set())
    return cats
