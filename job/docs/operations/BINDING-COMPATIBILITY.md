# Binding Compatibility

Canonical Engineering binding: `FORGE-OPS-HIGHEND-v1.0.0`.

For MCH-S001@1.0.0, the Founder-authorized compatibility rule treats exactly these two serializations as the same binding family/version:

- `FORGE-OPS-HIGHEND-v1.0.0`
- `FORGE-OPS-HIGHEND/v1.0.0`

Both resolve to family `FORGE-OPS-HIGHEND` and version `1.0.0`.

Validation remains fail-closed: any different family/version, wildcard, prefix/substring match, case variant, missing version, or unknown separator is configuration drift.

This compatibility changes only serialization comparison. It does not relax repository boundaries, authorization, no-Python, public-repository safety, Slice scope, GAUNTLET, candidate identity, or promotion requirements.

The repository-owned verification layer must test both accepted serializations and reject every other form.
