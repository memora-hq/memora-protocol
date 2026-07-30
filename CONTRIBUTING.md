# Contributing

`@smritheon/memora-protocol` is an open-source developer preview under Apache 2.0.
Contributions are welcome — bug fixes, documentation improvements, additional conformance
vectors, and protocol discussion all help.

## Before you start

**Open an issue first for anything that touches a signing digest, wire format, or Merkle proof
structure.** These are breaking changes by definition (see the Versioning section in
`README.md`) and need discussion before implementation. Small fixes (typos, broken links,
non-normative doc corrections) can go straight to a PR.

**This repo does not accept changes to hosted infrastructure**, because there isn't any here —
no service, no database, no deployment config. If your change needs one of those, it belongs in
Memora's private hosted repository instead.

## Development setup

```bash
pnpm install
pnpm build
pnpm test
```

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make changes. Keep commits focused — one logical change per commit.
3. If your change touches signing digests, wire format, or Merkle proofs: add or update a
   conformance vector in `vectors/` (append-only — never edit or remove an existing vector) and
   bump the version per the rules in `README.md`.
4. Run `pnpm build && pnpm test` locally before pushing. CI runs the same, plus the vector suite.
5. Open the PR against `main`.

## Code style

TypeScript throughout. No `any` without justification. No comments explaining *what* code does
— only *why*, when the reason is non-obvious (a hidden constraint, a workaround, a subtlety a
future reader would otherwise miss).

## Sign-off

Commits should include a `Signed-off-by` line (`git commit -s`) certifying you wrote the change
or otherwise have the right to submit it under this project's license (Developer Certificate of
Origin).
