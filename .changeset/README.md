# Changesets

Scratchsmith uses a **changesets-only** release model driven by [knope](https://knope.tech).
Every user-facing change adds a fragment here; those fragments (not commit messages)
drive both the version bump and the `CHANGELOG.md` entry.

## Add one

```sh
knope document-change
```

…or hand-write `.changeset/<slug>.md`:

```markdown
---
default: minor
---

#### A one-line summary of the change

Optional longer details.
```

`default:` is one of `patch`, `minor`, `major`, `perf`, `security`. **Pre-1.0**, knope
maps `major` (a breaking change) to a *minor* bump — 0.x never auto-bumps to 1.0.

Internal-only PRs (CI, refactor, tests, non-user-facing docs) need no fragment — apply
the **`no-changelog`** label instead.

`CHANGELOG.md` is generated from these fragments; never hand-edit it.
