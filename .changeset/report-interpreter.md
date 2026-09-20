---
default: minor
---

#### The pack report names the loader

`pack --format json` gains an `interpreter` field, and the text output gains a `loader` line.
Both carry the image path of the dynamic loader, which is the one staged path the binary's
`PT_INTERP` chooses rather than scratchsmith. A static binary needs no loader, so the field is
null and the text line is absent.

Until now a pack recorded every other fact about the image and stayed silent about the loader.
A job that wanted to assert which loader shipped had to unpack the image and look. It can now
read one field.

The field is additive, so an existing consumer of the JSON is unaffected.
