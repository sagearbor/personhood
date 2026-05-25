# src/policy

Policy DSL parser and evaluator. Integrators declare policies in YAML or JSON ("for action X, require ≥1 anchor + N supplementary points + max credential age T"); the evaluator checks presented credentials against them and returns a structured `EvaluationResult`.

The DSL **rejects naive weighted-sum stacking**: if `anchor_required: true`, summing supplementary points alone cannot satisfy the policy regardless of total. See the design plan for the full DSL spec.
