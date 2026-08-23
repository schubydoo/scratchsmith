---
name: Feature Request
about: Suggest an improvement or a new capability
title: '[FEATURE] '
labels: enhancement
assignees: ''
---

## The problem

What are you trying to do that Scratchsmith doesn't handle well today?

## Proposed solution

What would you like it to do? A flag, a new sink, a resolver behaviour, etc.

## Alternatives considered

Other tools or workarounds you've tried (dockerize, static linking, hand-rolled
multi-stage builds, …) and why they fall short here.

## Scope check

Scratchsmith targets **prebuilt dynamic glibc Linux binaries**. It deliberately
does not: resolve musl binaries, resolve cross-arch deps, or replace static
linking for binaries you can rebuild static. Does your request fit that scope?

## Additional context

Anything else — a concrete binary, a use case, a link.
