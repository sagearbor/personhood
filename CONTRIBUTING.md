# Contributing to Personhood

Thanks for your interest. Personhood is in early development; we welcome issues, design feedback, and PRs.

## Filing issues

Open a GitHub issue. Include:

- What you tried (commands, code, OS, language versions)
- What you expected vs. what happened
- For design proposals, a short "why" plus at least one alternative you considered

For **security** issues, **do not open a public issue**. See [SECURITY.md](SECURITY.md).

## Branch naming

- `feat/<short-name>` — new functionality
- `fix/<short-name>` — bug fixes
- `docs/<short-name>` — documentation only
- `refactor/<short-name>` — non-behavioral changes
- `test/<short-name>` — adding or updating tests

## Pull-request process

1. Fork the repo and create your branch from `main`.
2. Keep PRs focused — one logical change per PR. If you find an unrelated bug while working, file a separate issue or PR.
3. Update relevant docs (READMEs, `INTERFACE.md` files, design specs in `docs/`) in the same PR as the code change.
4. Add or update tests for behavioral changes.
5. Open the PR with a clear title and a description that explains *why*, not just *what*.
6. CI must pass. A maintainer will review; address feedback as new commits (don't force-push during review unless asked).

## Code style

- **Go** — `gofmt` (enforced). Prefer the standard library; justify third-party dependencies in the PR description. Use the module path `github.com/sagearbor/personhood/...`.
- **TypeScript** — `prettier` + `eslint` (config to land with the first TS implementation). Strict mode, ES2022 target.
- **Commit messages** — present tense ("Add X", not "Added X"). One concise subject line, optional body explaining the why.

## License / CLA

By submitting a contribution, you agree that your contribution is licensed under the Apache License, Version 2.0 (see [LICENSE](LICENSE)). No separate CLA is required at this time.
