"""
PoC: apply_redaction() (r6/redaction.py) leaves PHI in place when it lives in a field the
field-list redactor doesn't traverse. It walks a fixed set of fields (name, birthDate,
photo, text, identifier, address, telecom, contact, note, comment) plus one level of
`contained[]`. Anything else passes through verbatim — breaking the documented guarantee
"Standard redaction profile for PHI protection applied consistently on all resource access
paths." This loads the project's REAL redaction module (no project deps needed; it imports
only json).
"""
import importlib.util
import json
import os

HERE = os.path.join(os.path.dirname(__file__), "HealthClawGuardrails", "r6", "redaction.py")
spec = importlib.util.spec_from_file_location("redaction", HERE)
red = importlib.util.module_from_spec(spec)
spec.loader.exec_module(red)
apply_redaction = red.apply_redaction


def leaked(obj, needles):
    blob = json.dumps(obj)
    return [n for n in needles if n in blob]


PHI = ["Johnathan", "Rivera", "123-45-6789", "555-867-5309", "hidden.email@x.com"]

# 1) PHI in a resource-level extension — never traversed.
patient = {
    "resourceType": "Patient",
    "name": [{"family": "Rivera", "given": ["Johnathan"]}],
    "extension": [{
        "url": "https://evil.example/full-name",
        "valueString": "Johnathan Rivera, SSN 123-45-6789",
    }],
}

# 2) PHI in free-text value fields (valueString / component) — not covered.
observation = {
    "resourceType": "Observation",
    "status": "final",
    "valueString": "Patient Johnathan Rivera reports pain; contact 555-867-5309",
    "component": [{"valueString": "hidden.email@x.com"}],
}

# 3) PHI in DiagnosticReport.conclusion — free text, not covered.
report = {
    "resourceType": "DiagnosticReport",
    "status": "final",
    "conclusion": "Johnathan Rivera (SSN 123-45-6789): findings consistent with ...",
}

# 4) A search Bundle — apply_redaction only recurses into contained[], never entry[].resource.
bundle = {
    "resourceType": "Bundle",
    "type": "searchset",
    "entry": [{"resource": {
        "resourceType": "Patient",
        "name": [{"family": "Rivera", "given": ["Johnathan"]}],
        "telecom": [{"system": "phone", "value": "555-867-5309"}],
    }}],
}

for label, res in [
    ("resource-level extension", patient),
    ("Observation.valueString / component", observation),
    ("DiagnosticReport.conclusion", report),
    ("Bundle.entry[].resource (search result)", bundle),
]:
    out = apply_redaction(res)
    survived = leaked(out, PHI)
    print(f"[{'LEAK' if survived else 'ok  '}] {label}: PHI still present -> {survived}")

print("\nExample — redacted Patient still carries the full name + SSN in its extension:")
print(json.dumps(apply_redaction(patient), indent=2))
