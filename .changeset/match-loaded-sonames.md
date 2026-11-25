---
default: patch
---

#### A library that two objects need now resolves like ld.so

`pack` and `graph` failed with "unresolved dependencies" when a library was needed by the program and by another library, and only the program had a RUNPATH for it. The resolver now uses a library that is already loaded under that name, as the loader does. With a custom `PT_INTERP`, libc's dependency on the loader now resolves to that loader, so the image no longer gets a second, host copy of it.
