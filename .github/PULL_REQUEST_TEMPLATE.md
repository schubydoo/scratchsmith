## Description

What does this change and why?

## Related issue

Fixes #(issue number)

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (changes existing behavior)
- [ ] Documentation
- [ ] Refactor / internal (no behavior change)

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --all-features` passes on Linux (Docker/`cc` tests skip without
      those tools locally, and fail rather than skip in CI)
- [ ] Added or updated tests for the change
- [ ] Added a `.changeset/<slug>.md` fragment (or the `no-changelog` label applies).
      For a user-visible change, also updated the docs. `CHANGELOG.md` is generated,
      never hand-edited
- [ ] Commits follow Conventional Commits, and the PR targets `main`
- [ ] Kept Scratchsmith's invariants: fail loud never silent, emulate `ld.so` (never
      scrape host `ldd`/env), non-root images, reproducible layers, no overstated claims

## Notes for reviewers

Anything that needs extra attention, or manual steps to verify.
