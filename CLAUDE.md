# CLAUDE.md

**The shared agent instructions for this repo live in [AGENTS.md](AGENTS.md). The `@`
line below imports that file, so it loads together with this one. You do not need to open
it separately.**

@AGENTS.md

⚠️ **That `@AGENTS.md` line does real work. Do not "tidy" it into a plain link.**
Claude Code reads `CLAUDE.md`, not `AGENTS.md`. A markdown link is only a suggestion, and
an agent can ignore it. The `@` form is an import that Claude Code expands into context at
launch. `@` is inert inside backticks or code fences, so `` `@AGENTS.md` `` in prose does
NOT import.

---

`CLAUDE.local.md` is gitignored and loads *after* this file. Host-specific paths and
personal tooling notes belong there, not here.
