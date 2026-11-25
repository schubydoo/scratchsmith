---
default: patch
---

#### --strip and the size report cover the NSS modules

`--strip` left the staged NSS modules unstripped, and the size report did not list them, though they ship in the image. Both now include them. The size report totals grow by the size of the modules. With `--strip`, the image gets smaller, and so does the total that `--max-size` checks.
