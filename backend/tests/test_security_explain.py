import json

import pytest

from apps.core.models import AppConfiguration
from apps.security_engine import explain as E
from apps.security_engine.models import SecurityCheck
from tests.conftest import enable_provider
from tests.netfakes import http_response

pytestmark = pytest.mark.django_db
URL = "/api/v1/security/analyze/"


def trig(rule, strength="moderate", weight=30, severity="medium", code="x"):
    return {"rule": rule, "name": rule, "strength": strength, "weight": weight, "severity": severity,
            "reason_code": code, "status": "triggered", "message": "dynamic text with /secret/path?q=1"}


def evidence(cls="suspicious", rules=None, missing=()):
    rules = rules if rules is not None else [trig("url.brand_keyword_combo", code="brand_keyword_combo"),
                                              trig("tls.no_https", "weak", 8, "low", "no_https")]
    return E.build_evidence(classification=cls, risk_score=40, confidence="medium", host="paypal-secure-login.com",
                            scheme="http", rules=rules, threat={"ok_count": 1, "confirmed": []}, domain=None,
                            missing_checks=list(missing), shortened=False)


def good_ai(ev, **over):
    obj = {"summary": "The address pairs a brand name with a sign-in keyword on an unrelated domain.",
           "classification": ev["classification"],
           "key_findings": [{"finding": ev["findings"][0]["finding"], "explanation": "Brands use their own domains.", "severity": "medium"}],
           "recommended_actions": ["Type the brand's real address yourself."], "limitations": ["Not proof of fraud."]}
    obj.update(over)
    return obj


# ---- evidence minimisation ------------------------------------------------------------------------------------------
def test_evidence_contains_only_static_facts_and_the_host():
    ev = evidence()
    blob = json.dumps(ev)
    assert ev["destination"] == {"host": "paypal-secure-login.com", "scheme": "http", "reached_through_url_shortener": False}
    assert "/secret/path" not in blob and "q=1" not in blob and "dynamic text" not in blob     # no dynamic/user text
    assert ev["findings"][0]["meaning"] and ev["findings"][0]["finding"] == "url.brand_keyword_combo"
    assert set(ev) == {"classification", "classification_label", "risk_score", "confidence", "destination", "findings",
                       "threat_intelligence", "domain", "missing_checks"}


def test_evidence_limits_findings_and_orders_by_weight():
    rules = [trig("url.shortener", "weak", 10), trig("url.ip_host", "moderate", 25), trig("url.mixed_scripts", "strong", 45)]
    assert [f["finding"] for f in evidence(rules=rules)["findings"]] == ["url.mixed_scripts", "url.ip_host", "url.shortener"]


# ---- rule-based explanation --------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("cls", list(E._SUMMARY))
def test_rule_based_explanation_exists_for_every_classification_and_never_claims_safety(cls):
    ex = E.rule_based_explanation(evidence(cls=cls, missing=["rdap"]))
    assert ex["source"] == "rule_based" and ex["classification"] == cls and ex["summary"]
    assert not E.FORBIDDEN.search(json.dumps(ex))
    assert any("trustworthy" in x for x in ex["limitations"]) and any("Rdap" in x for x in ex["limitations"])


def test_rule_based_content_by_severity():
    assert "will not forward" in E.rule_based_explanation(evidence("known_malicious"))["summary"]
    assert "not a guarantee" in E.rule_based_explanation(evidence("no_known_threat_detected", rules=[]))["summary"]
    risky = E.rule_based_explanation(evidence("suspicious"))
    assert any("passwords or payment" in a for a in risky["recommended_actions"]) and len(risky["key_findings"]) == 2
    clean = E.rule_based_explanation(evidence("no_known_threat_detected", rules=[]))
    assert not any("passwords or payment" in a for a in clean["recommended_actions"])
    assert any("Confirm the destination" in a for a in E.rule_based_explanation(evidence("needs_further_verification"))["recommended_actions"])


# ---- validation of AI output ----------------------------------------------------------------------------------------------------
def test_valid_ai_output_is_accepted_and_normalised():
    ev = evidence()
    out = E.validate_explanation({**good_ai(ev), "extra": "ignored"}, ev)
    assert out["source"] == "ai" and "extra" not in out and out["classification"] == "suspicious"


@pytest.mark.parametrize("mutate", [
    lambda ev: "not a dict",
    lambda ev: good_ai(ev, summary=""), lambda ev: good_ai(ev, summary="x" * 601),
    lambda ev: good_ai(ev, classification="no_known_threat_detected"),     # AI may never change the verdict
    lambda ev: good_ai(ev, classification="known_malicious"),
    lambda ev: good_ai(ev, key_findings=[{"finding": "url.invented_rule", "explanation": "x", "severity": "high"}]),
    lambda ev: good_ai(ev, key_findings=[{"finding": ev["findings"][0]["finding"], "explanation": "x", "severity": "catastrophic"}]),
    lambda ev: good_ai(ev, key_findings=[{"finding": ev["findings"][0]["finding"], "explanation": "x" * 401, "severity": "low"}]),
    lambda ev: good_ai(ev, key_findings="oops"),
    lambda ev: good_ai(ev, recommended_actions=["ok", 5]), lambda ev: good_ai(ev, recommended_actions=["x" * 241]),
    lambda ev: good_ai(ev, recommended_actions=["a"] * 9), lambda ev: good_ai(ev, limitations=["a"] * 7),
    lambda ev: {k: v for k, v in good_ai(ev).items() if k != "limitations"},
])
def test_invalid_ai_output_is_rejected(mutate):
    ev = evidence()
    with pytest.raises(E.ExplanationInvalid):
        E.validate_explanation(mutate(ev), ev)


@pytest.mark.parametrize("claim", ["This site is 100% safe.", "It is completely safe to visit.", "You can safely say it is guaranteed safe",
                                   "Totally safe.", "It is safe to open this link.", "There is no risk here.", "A risk-free page."])
def test_ai_safety_claims_are_rejected_wherever_they_appear(claim):
    ev = evidence()
    for field in ("summary", "recommended_actions", "limitations"):
        obj = good_ai(ev)
        obj[field] = claim if field == "summary" else [claim]
        with pytest.raises(E.ExplanationInvalid):
            E.validate_explanation(obj, ev)
    obj = good_ai(ev)
    obj["key_findings"][0]["explanation"] = claim
    with pytest.raises(E.ExplanationInvalid):
        E.validate_explanation(obj, ev)


# ---- fallback behaviour ---------------------------------------------------------------------------------------------------------------
@pytest.fixture
def ai_on(settings):
    settings.AI_PROVIDER, settings.AI_API_KEY = "anthropic", "sk-test-123"


def test_ai_is_used_when_valid_including_fenced_json(ai_on, monkeypatch):
    ev = evidence()
    monkeypatch.setattr(E, "call_anthropic", lambda e, g: "```json\n" + json.dumps(good_ai(e)) + "\n```")
    assert E.explain(ev, use_ai=True, guard=None)["source"] == "ai"


@pytest.mark.parametrize("reply", ["not json at all", "{}", json.dumps({"summary": "x"}), "[]"])
def test_garbage_ai_output_falls_back_to_the_standard_explanation(ai_on, monkeypatch, reply):
    ev = evidence()
    monkeypatch.setattr(E, "call_anthropic", lambda e, g: reply)
    ex = E.explain(ev, use_ai=True, guard=None)
    assert ex["source"] == "rule_based" and "ai_error" in ex and ex["classification"] == "suspicious"


def test_ai_that_changes_the_classification_or_invents_findings_is_discarded(ai_on, monkeypatch):
    ev = evidence()
    for bad in (good_ai(ev, classification="no_known_threat_detected"),
                good_ai(ev, key_findings=[{"finding": "intel.known_malware", "explanation": "x", "severity": "critical"}])):
        monkeypatch.setattr(E, "call_anthropic", lambda e, g, bad=bad: json.dumps(bad))
        ex = E.explain(ev, use_ai=True, guard=None)
        assert ex["source"] == "rule_based" and ex["classification"] == "suspicious"


def test_ai_outage_falls_back(ai_on, monkeypatch):
    def down(e, g):
        raise E.ExplanationInvalid("ai_unavailable:timeout")
    monkeypatch.setattr(E, "call_anthropic", down)
    assert E.explain(evidence(), use_ai=True, guard=None)["source"] == "rule_based"


def test_ai_is_not_called_unless_requested_and_configured(settings, monkeypatch):
    calls = []
    monkeypatch.setattr(E, "call_anthropic", lambda e, g: calls.append(1) or "{}")
    ev = evidence()
    assert E.explain(ev, use_ai=True, guard=None)["source"] == "rule_based"          # not configured
    settings.AI_PROVIDER, settings.AI_API_KEY = "anthropic", "k"
    assert E.explain(ev, use_ai=False, guard=None)["source"] == "rule_based"         # not requested
    settings.AI_API_KEY = ""
    assert E.explain(ev, use_ai=True, guard=None)["source"] == "rule_based"          # no key
    assert calls == []


# ---- the real HTTP call, through the SSRF guard ------------------------------------------------------------------------------------------
def anthropic_server(senv, *, reply=None, status=200):
    seen = {}

    def handler(req):
        head, _, body = req.partition("\r\n\r\n")
        seen["head"], seen["body"] = head, body
        payload = json.loads(body)
        evidence_obj = json.loads(payload["messages"][0]["content"])
        seen["evidence"] = evidence_obj
        obj = reply(evidence_obj) if reply else good_ai(evidence_obj)
        return http_response(status, json.dumps({"content": [{"type": "text", "text": json.dumps(obj)}]}),
                             {"Content-Type": "application/json"})
    senv.world.site("api.anthropic.com", "160.79.104.10", https=handler)
    return seen


def test_signed_in_user_gets_an_ai_explanation_and_only_whitelisted_data_is_sent(auth_client, senv, ai_on):
    senv.publish("paypal-secure-login.com")
    seen = anthropic_server(senv)
    r = auth_client.post(URL, {"url": "http://paypal-secure-login.com/account/reset?token=TOPSECRET#frag", "ai": True}, format="json")
    assert r.status_code == 200 and r.data["explanation"]["source"] == "ai"
    assert r.data["classification"] == "suspicious"                    # the verdict is still the engine's
    head, body = seen["head"].lower(), seen["body"]
    assert head.startswith("post /v1/messages") and "x-api-key: sk-test-123" in head and "anthropic-version:" in head
    payload = json.loads(body)
    assert payload["model"] == "claude-sonnet-5-5" and "Never invent" in payload["system"]
    for leak in ("TOPSECRET", "frag", "/account/reset", "token=", "dynamic"):
        assert leak not in body, leak
    assert seen["evidence"]["destination"]["host"] == "paypal-secure-login.com"
    assert "sk-test-123" not in json.dumps(r.data, default=str)


def test_anonymous_users_never_trigger_ai_calls(api, senv, ai_on):
    senv.publish("paypal-secure-login.com")
    seen = anthropic_server(senv)
    r = api.post(URL, {"url": "http://paypal-secure-login.com/", "ai": True}, format="json")
    assert r.data["explanation"]["source"] == "rule_based" and seen == {}


def test_ai_feature_flag_is_enforced_on_the_backend(auth_client, senv, ai_on):
    senv.publish("paypal-secure-login.com")
    seen = anthropic_server(senv)
    AppConfiguration.objects.create(key="default_entitlements", value={"ai.explanations": False})
    r = auth_client.post(URL, {"url": "http://paypal-secure-login.com/", "ai": True}, format="json")
    assert r.data["explanation"]["source"] == "rule_based" and seen == {}


def test_a_model_that_tries_to_change_the_verdict_is_ignored_end_to_end(auth_client, senv, ai_on):
    senv.publish("paypal-secure-login.com")
    anthropic_server(senv, reply=lambda ev: good_ai(ev, classification="no_known_threat_detected",
                                                    summary="Everything is fine."))
    r = auth_client.post(URL, {"url": "http://paypal-secure-login.com/", "ai": True}, format="json")
    assert r.data["classification"] == "suspicious" and r.data["explanation"]["source"] == "rule_based"
    assert "ai_error" in r.data["explanation"] and "Everything is fine" not in json.dumps(r.data, default=str)


def test_ai_provider_outage_still_returns_the_findings(auth_client, senv, ai_on):
    senv.publish("paypal-secure-login.com")
    senv.world.site("api.anthropic.com", "160.79.104.10", https=lambda r: http_response(503, "{}"))
    r = auth_client.post(URL, {"url": "http://paypal-secure-login.com/", "ai": True}, format="json")
    assert r.status_code == 200 and r.data["explanation"]["source"] == "rule_based" and r.data["findings"]


def test_a_cached_check_is_upgraded_to_an_ai_explanation_when_a_signed_in_user_asks(api, auth_client, senv, ai_on):
    senv.publish("paypal-secure-login.com")
    anthropic_server(senv)
    first = api.post(URL, {"url": "http://paypal-secure-login.com/"}, format="json").data
    assert first["explanation"]["source"] == "rule_based"
    second = auth_client.post(URL, {"url": "http://paypal-secure-login.com/", "ai": True}, format="json").data
    assert second["cached"] is True and second["id"] == first["id"] and second["explanation"]["source"] == "ai"
    assert SecurityCheck.objects.count() == 1
