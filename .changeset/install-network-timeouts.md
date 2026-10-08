---
default: patch
---

#### `install.sh` no longer hangs on a stalled connection

The installer set no network timeout, so a connection that stalled left it waiting with no output.
If no data arrives for 30 seconds, it now gives up and prints the download error. A slow
connection that still moves data is not cut off.
