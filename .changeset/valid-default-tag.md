---
default: patch
---

#### The default image tag is valid for any binary name

A binary named with a `+`, a space, a leading dot or a non-ASCII letter, like `c++filt`, gave a default tag `docker load` refused. Each character a tag can't hold now becomes `-`, and a leading or trailing separator is dropped, so `c++filt` is tagged `scratchsmith/c--filt:packed`. A UTF-8 name that already made a valid tag keeps it. A name that is not valid UTF-8 used to get `scratchsmith/image:packed`, and now gets a tag from its name, where the bytes that are not UTF-8 count as characters a tag can't hold.
