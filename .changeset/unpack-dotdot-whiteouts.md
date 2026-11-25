---
default: security
---

#### unpack honors a whiteout whose path has a `..` part

A whiteout marker such as `etc/../etc/.wh.keep` was skipped, so `etc/keep` stayed in the unpacked tree, while Docker deletes it. `unpack` now cleans the marker's path as Docker does and deletes what it names. A rooted `..` stops at `/`, so `/../etc/.wh.keep` deletes `etc/keep` too. A relative marker whose `..` climbs above the root, such as `../.wh.x`, is refused, as Docker refuses it: the layer is not applied, and `unpack` exits `1`.
