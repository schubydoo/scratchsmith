---
default: patch
---

#### The GitHub Action no longer hangs on a stalled download

The action downloaded the release with no network timeout, so a connection that stalled held the
step until the job timed out. If no data arrives for 30 seconds, the download now stops, and the
step fails after three more tries. A slow connection that still moves data is not cut off.
