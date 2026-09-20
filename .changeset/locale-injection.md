---
default: minor
---

#### `--locale`: stage a glibc locale in the image

`pack --locale en_US.UTF-8` stages one compiled locale at `/usr/lib/locale/en_US.UTF-8`. With no
`LOCPATH` set, glibc reads exactly that path. Until now a scratch image carried no locale data.
Every packed binary ran in the C locale, and `setlocale` failed for any other. The data
comes from a matching host directory under `/usr/lib/locale`. When there is none, `localedef`
compiles the locale from the glibc sources at `/usr/share/i18n`. When neither source is
available, the pack fails and names what is missing.

The host `locale-archive` is never copied, because one archive holds every locale the host has.
A single locale costs about 3 MB, and most of that is the collation table `LC_COLLATE`.

Staging the data does not select it, so set `LANG` or `LC_ALL` with `--env`. If you stage a
locale and set neither, the pack warns. The flag repeats, takes a locale name and not a path,
and the `locale` key in `scratchsmith.toml` takes the same list.
