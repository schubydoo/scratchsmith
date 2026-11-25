---
default: security
---

#### unpack honors a whiteout with an absolute path

unpack extracted a file with an absolute path such as `/etc/secret`, but ignored a whiteout with one, so a later layer's `/etc/.wh.secret` left the file in the unpacked tree, though the image deletes it. A marker's leading `/` and `.` parts now drop, as an entry's do, and the deletion still runs inside the target.
