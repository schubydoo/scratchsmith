---
name: Feature Request
about: Suggest an improvement or a new capability
title: '[FEATURE] '
labels: enhancement
assignees: ''
---

## The problem

What are you trying to do that Scratchsmith does not handle well today?

## Proposed solution

What do you want it to do? Name the flag, the new sink, or the resolver behavior.

## Alternatives considered

Other tools or workarounds you tried (dockerize, static linking, hand-rolled
multi-stage builds, and the rest). Say why they fall short here.

## Scope check

Scratchsmith targets **prebuilt dynamic glibc Linux binaries**. It deliberately
does not: resolve musl binaries, resolve cross-arch deps, or replace static
linking for binaries you can rebuild static. Does your request fit that scope?

## Additional context

Anything else that helps. A concrete binary, a use case, a link.
