---
default: patch
---

#### --strip and the size report cover the NSS modules

`--strip` left the staged NSS modules unstripped, and the size report did not count them, though they ship in the image. Both now include them. The total that `--max-size` checks grows by their size, which is what the image already held.
