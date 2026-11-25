---
default: patch
---

#### unpack no longer fails on a read-only directory

Run as a user who is not root, `unpack` failed with "Permission denied" when a layer held a directory without owner write permission, such as `/root` in Fedora and UBI images. It now keeps each such directory open to its owner while it extracts, and applies the image's mode after the last layer. A failed unpack leaves a tree that its owner can remove without `chmod`.
