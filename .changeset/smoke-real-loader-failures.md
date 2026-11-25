---
default: patch
---

#### --smoke reports only real loader failures, and ends at its limit

`--smoke` failed the pack for any app whose error output held "no such file or directory", such as an app that could not find its own config file. It now counts that phrase only on the runtime's own line for an entrypoint it could not exec. A long-running entrypoint that ignores SIGTERM, such as a server running as PID 1, could also keep the smoke run waiting for good. The run now removes its container at the limit, so it ends and leaves no container behind.
