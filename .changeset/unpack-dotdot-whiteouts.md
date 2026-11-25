---
default: patch
---

#### unpack honors a whiteout whose path has a `..` part

A whiteout marker such as `etc/../etc/.wh.keep` was skipped, so `etc/keep` stayed in the unpacked tree, while Docker deletes it. `unpack` now cleans the marker's path inside the image root, as Docker does, and deletes what it names. A marker whose `..` climbs above the root is refused, and the layer is not applied.
