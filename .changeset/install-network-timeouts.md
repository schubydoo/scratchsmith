---
default: patch
---

#### `install.sh` no longer hangs on a stalled connection

The installer set no network timeout, so a connection that stalled left it waiting with no output.
It now gives up when no data arrives for 30 seconds and prints the download error. With `wget` it
tries one more time first. A slow connection that still moves data is not cut off.
