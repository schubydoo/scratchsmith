---
default: minor
---

#### `diff` compares file modes and empty directories

`diff` now reports a regular file or directory whose permission bits differ between the two trees, such as a lost exec bit or a world-writable directory, and an empty directory that is in only one tree. Before, it compared contents and symlink targets only, so `diff --exit-code` passed both. The JSON output gains three fields, `mode_changed`, `dirs_added` and `dirs_removed`. Existing fields are unchanged. A `pack --no-build --output` tree keeps the host's modes, which the image layer rewrites, so a drift gate that diffs two staged trees from builders with different umasks now fails on modes the images do not carry. Stage both builds on one builder, or `unpack` both images and diff those.
