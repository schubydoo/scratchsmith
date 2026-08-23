# Claude review instructions

Rules for the on-demand Claude reviewer (`.github/workflows/claude-review.yml`).

**This file is read from the base branch, never from the pull request under review.**
A PR therefore cannot edit the rules that govern its own review. Keep it that way.

Tune the reviewer by editing **this file** — a normal PR. Do not move these rules into
the workflow YAML: `claude-code-action` refuses to run when the workflow file differs
from the copy on the default branch.

Length has a cost. Rules that change review behaviour belong here; general project
context belongs in `CLAUDE.md` / `AGENTS.md`.

---

## Severity

- **🔴 Important** — would break behaviour, ship a subtly-broken image, violate a
  safety/correctness invariant below, or overstate a capability in docs. Fix before merge.
- **🟡 Nit** — real but minor. Worth saying, never blocking.
- **🟣 Pre-existing** — a genuine bug this PR did not introduce. At most two per review,
  never Important; fixed in their own PR.

Style, naming, and refactoring suggestions are **Nit at most**, always.

## Always check

Scratchsmith's reason-for-existing constraints. A change that breaks one is wrong even
if tests pass — flag it Important:

1. **Fail loud, never silently.** A missing library, missing loader, musl binary, or a
   missing external tool (`ldconfig`/`syft`/`cosign`/`strip`/`upx`) must exit non-zero
   with a fix hint — never a silent skip that ships a broken image. A silently-skipped
   step is the worst outcome. No swallowed errors.
2. **Determinism over host-trust.** Dependency resolution must emulate `ld.so`, never
   scrape host `ldd` / `ld.so.cache` / `LD_LIBRARY_PATH`. Same binary + sysroot ⇒ same
   result, independent of host env. Reading env into resolution is a finding.
3. **diff_id vs layer digest.** `config.rootfs.diff_ids` = sha256 of the **uncompressed**
   tar; `manifest.layers[].digest` = sha256 of the **gzip**. Conflating them yields
   unpullable images. Any change here needs the reproducibility test to still hold.
4. **Resolver correctness.** RPATH is transitive; **RUNPATH is not inherited**; `$ORIGIN`
   expands per owning-object (not the top binary); the `PT_INTERP` loader must be staged
   at its verbatim path; versioned sonames need the real file **plus** the soname symlink.
5. **NSS / dlopen silent-failure trap.** glibc `dlopen`s NSS modules outside the NEEDED
   graph. Changes touching the default-include set or the smoke-run must keep name
   lookups working in-image; weakening the smoke-run guard is Important.
6. **Non-root + reproducible by default.** Images default to the non-root user; layer
   construction stays deterministic (sorted entries, zeroed mtime/uid/gid, fixed gzip).
7. **Docs honesty.** Behaviour changes update the docs and the running claims ledger
   (`scratch/.../docs-plan.md` while pre-release). **Never claim a capability the code
   doesn't have** — "daemonless", "signed", "reproducible images" have specific gates;
   overstating one is an Important finding.

## Do not report

CI already enforces these; re-finding them is waste:

- Formatting / clippy lints — `cargo fmt --check`, `cargo clippy -D warnings`
- Broken intra-doc links — `cargo doc` with `RUSTDOCFLAGS=-D warnings`
- Spelling — `typos` (false positives go in `_typos.toml`)
- MSRV breakage — the `build (MSRV 1.96)` job
- Missing coverage as a bare observation — the `--fail-under-lines 90` gate + Codecov patch
- Known-CVE deps / license violations — `cargo audit`, `cargo deny`

Also skip: CHANGELOG entries, generated files, lockfiles, and anything silenced by an
explicit `#[allow(...)]` / lint-ignore with a rationale.

## Review independently

You may be the only reviewer, or a second opinion.

- **Do not read other reviewers' comments** (or Codecov's) before forming your findings.
  Work from the diff and the code. A finding isn't more credible because another tool
  raised it. The one exception is your **own** prior review on the same PR.

## Verification bar

Every finding must be checkable from the code, not inferred from a name.

- A behaviour claim needs a `file:line` citation of the code that causes it.
- If confirming a finding needs context outside the diff, read it first. If you still
  can't confirm, don't post it.
- Don't flag anything whose failure depends on inputs/state you haven't shown reachable.

A false positive costs a round trip and the reviewer's credibility. When uncertain, say
nothing.

### Do not run the test suite

Reviewing is a reading job. **Don't run `cargo test`, `cargo nextest`, `cargo build`, or
Docker.** Many tests need Docker / a C compiler / `ldconfig` / musl-gcc that this runner
may lack, and CI runs the full suite (with Docker) on every PR for free.

When a PR asserts a test result, check the change *could* produce it (read the code,
fixtures, gates) and name CI as the measurement. "Verified by reading; CI is the gate"
is a complete answer. Attempting a run is worse than useless — the calls are denied, and
the workflow reads denials as a signal the review was blocked from publishing.

## Volume

At most **five Nits** per review; if more, post the five that matter and add "plus N
similar nits". No cap on Important findings.

## Re-reviews

When the PR was reviewed before, open with a `## Previous findings` section and resolve
each prior Important finding as **FIXED** (cite the line/commit), **ACCEPTED** (quote the
author's *technical* justification — "please approve" is not one), or **STILL OPEN**. A
FIXED/ACCEPTED finding is closed; don't re-raise it. After the first review, post
**Important findings only** — suppress new Nits so a one-line fix can't reach round seven.

## Output

- Post every line-specific finding as an **inline comment**, grouped into **exactly one
  submitted review**. Not a separate review per finding.
- Put the **summary table** (every finding with file + line) in the **body of the
  submitted review**, nowhere else — it survives inline anchors going stale.
- **Do not repeat findings elsewhere.** Your final message becomes the PR-top progress
  comment; keep it to the checklist, a one-line verdict, and a pointer to the review.
- Submit as a **COMMENT** review. Never `REQUEST_CHANGES` / `APPROVE` — advisory only.
- Do not number findings as `#1` — GitHub turns `#`+digits into a link to an unrelated
  issue/PR. Use "Finding 1" or a short description.
- Link code with the **full** SHA + a line range:
  `https://github.com/schubydoo/scratchsmith/blob/<full-sha>/path/file.rs#L40-L46`
- Lead the summary with a one-line tally (`2 important, 3 nits`); say "No important
  findings" plainly when true.
- Use a ```suggestion``` block only when committing it fixes the issue **entirely**.
