# src/methods/email

**Supplementary method** (target strength 5–10).

Email verification via magic link (preferred over OTP — better UX, similar security). Checks against a maintained disposable-email block-list before issuing the challenge.

## Strength rationale

Email is weak. A bot farm can mint unlimited Gmail/Outlook addresses for free. This method exists to demonstrate the framework and to give integrators a "frictionless" low-stakes option (e.g. forum signup). It must NEVER satisfy a high-stakes policy on its own; the policy DSL's `anchor_required` flag enforces this.

## Future enhancement

Per-domain strength weighting (work-email domain → higher strength than free-mail) is a v0.2 candidate.
