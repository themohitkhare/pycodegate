# Changelog

## 0.5.0

- Add opt-in, path-scoped import boundaries to turn architectural constraints into
  deterministic `imports/boundary` errors with project-specific remediation guidance.
- Support absolute and relative static imports, aliases, nested imports, and
  type-checking blocks in conventional flat and `src/` layouts.
- Integrate boundaries with JSON, SARIF, CI failure thresholds, rule ignores,
  per-file suppression, and the lint toggle.
- Reject malformed boundary configuration with a readable CLI error.
- Enforce separation between PyCodeGate's analysis rules, shared data types, and
  presentation using the same boundary configuration available to users.

No import restrictions are enabled for projects without boundary configuration.
Dynamic imports, re-export tracing, and custom import roots are outside the scope
of this check. See the README for configuration and matching semantics.

This release also includes the precision, scoring, and output fixes already on
main after the published 0.3.0 release.
