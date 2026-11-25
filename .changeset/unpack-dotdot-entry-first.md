---
default: security
---

#### unpack refuses a layer with a `..` entry before its whiteouts run

A layer entry with a `..` part, such as `etc/../../x`, or a hard link whose target climbs above the image root, such as `../x`, was refused, but only after that layer's whiteouts had already deleted files from the unpacked tree. `unpack` now checks those names in every entry of a layer before it applies any whiteout, so a layer refused for one of them leaves the tree as the layers below it made it. It still exits `1`.
