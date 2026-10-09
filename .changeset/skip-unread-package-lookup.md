---
default: patch
---

#### A pack with the text report no longer looks up packages that it does not show

The default `--packages report` output is a list in the `--format json` report, and the text
report never showed it. A pack with the text report still ran the lookup, which was most of
the time of a small pack. It now skips the lookup unless you set `--packages`.
