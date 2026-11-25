---
default: patch
---

#### The root-user warning is a report warning

The warning for a root `--user` (`0`, `0:0` or `root`) was printed to stderr only, so a gate on the JSON report's `warnings` array missed it. It is now one of the report's warnings, and the text report still prints it.
