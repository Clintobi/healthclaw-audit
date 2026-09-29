# PHI redaction bypass in HealthClaw Guardrails — PHI passes through in untraversed FHIR fields

## Metadata

| | |
|---|---|
| Product | HealthClaw Guardrails (`aks129/HealthClawGuardrails`, healthclaw.io) |
| Version | commit `a531a8c5cb33cab8569fef613a8b6bccc3dc345f` (current `main`) |
| Component | `r6/redaction.py` — `apply_redaction` / `_redact_fields` (and `apply_patient_controlled_redaction`) |
| Vulnerability class | Incomplete PHI redaction / Information Exposure (CWE-200, CWE-359) |
| Severity | High — CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` (7.7) |

## Summary

HealthClaw's core guarantee is that a "Standard redaction profile for PHI protection [is]
applied consistently on all resource access paths." The redactor is field-list based: it
rewrites a fixed set of known FHIR fields (`name`, `birthDate`, `photo`, `text`,
`identifier`, `address`, `telecom`, `contact`, `note`, `comment`) and recurses one level
into `contained[]`. Any PHI that lives outside that fixed field set passes through verbatim.

Because FHIR carries free text and identifiers in many other places — element `extension[]`,
free-text value fields (`valueString`, `DiagnosticReport.conclusion`, component values), and
`Bundle.entry[].resource` — real clinical data routinely defeats the redactor. This is not a
crafted-payload edge case: clinician names and identifiers in narrative/observation fields
are ubiquitous, so PHI leaks under normal operation to the parties the guardrail is meant to
protect against (third-party LLM providers on the agent path, and external recipients on the
`$share-bundle` / SHL sharing path).

## Affected code

`r6/redaction.py`, `_redact_fields` only touches a fixed field list and `apply_redaction`
only recurses into `contained[]`:

```python
def apply_redaction(resource):
    redacted = json.loads(json.dumps(resource))
    _redact_fields(redacted)
    if 'contained' in redacted and isinstance(redacted['contained'], list):
        for contained in redacted['contained']:
            if isinstance(contained, dict):
                _redact_fields(contained)          # only contained[] — not entry[], not extensions
    return redacted
```

`_redact_fields` never inspects `extension` / `modifierExtension`, never inspects free-text
value fields, and `apply_redaction` never traverses `Bundle.entry[].resource`. The
`extension`-stripping in `r6/health_compliance.py` (`_is_identifying_extension`) is a
separate function and is not invoked on the `apply_redaction` path.

`apply_redaction` is applied directly to resources on read paths, e.g. `r6/routes.py:1300`
(`apply_redaction(obs.to_fhir_json())`) and lines 601/623/772/894/1050.

## Proof of concept

`poc_redaction_bypass.py` loads the project's real `r6/redaction.py` (it imports only
`json`, so no project dependencies are required) and applies `apply_redaction` to four
resources carrying PHI in untraversed locations:

```
python3 poc_redaction_bypass.py
```

Output:

```
[LEAK] resource-level extension: PHI still present -> ['Johnathan', 'Rivera', '123-45-6789']
[LEAK] Observation.valueString / component: PHI still present -> ['Johnathan', 'Rivera', '555-867-5309', 'hidden.email@x.com']
[LEAK] DiagnosticReport.conclusion: PHI still present -> ['Johnathan', 'Rivera', '123-45-6789']
[LEAK] Bundle.entry[].resource (search result): PHI still present -> ['Johnathan', 'Rivera', '555-867-5309']
```

The redacted Patient shows the control working on the known field yet leaking the same PHI
from an extension:

```json
{
  "resourceType": "Patient",
  "name": [{ "family": "R.", "given": ["J."] }],
  "extension": [{
    "url": "https://evil.example/full-name",
    "valueString": "Johnathan Rivera, SSN 123-45-6789"
  }]
}
```

The same gaps apply to `apply_patient_controlled_redaction` (the external-sharing path): it
removes `name`/`telecom`/`address`/`contact`/`note`/`text` but likewise does not touch
`extension`, `valueString`, `conclusion`, or `Bundle.entry[]`.

## Impact

PHI (names, SSNs, phone numbers, emails, and free-text identifiers) bypasses the redaction
control and reaches:
- **Third-party LLM providers** (OpenAI/Gemini adapters) on the agent path — the exact
  disclosure the product exists to prevent.
- **External recipients** on the `$share-bundle` / SmartHealthLink sharing path, where
  "deidentified" output still carries PHI.

Because the leak is driven by ordinary clinical content (narrative conclusions, string
observation values, US-Core extensions, and standard search Bundles), it occurs in normal
operation rather than requiring an attacker-crafted resource.

## Remediation

1. Make redaction default-deny: recursively walk the entire resource tree and redact by a
   PHI-field allowlist / typed schema, rather than rewriting a fixed set of top-level fields.
2. Traverse `extension[]` / `modifierExtension[]`, all string-valued elements (`valueString`,
   `conclusion`, component values, `Annotation.text`), and `Bundle.entry[].resource`.
3. Add a post-redaction assertion/scan (e.g., regex for SSN/phone/email plus the known
   patient names) that fails closed if any candidate PHI remains, so untraversed fields are
   caught rather than silently passed.

## Disclosure

Reported privately to security@healthclaw.io per the repository SECURITY.md, before any
public disclosure. Reporter: Clinton Obi, clinton.obi@vnsis.com.
