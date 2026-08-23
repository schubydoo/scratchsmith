//! Resolve a binary's shared-library deps by emulating the `ld.so` search order
//! (not by scraping host `ldd`). The correctness core; see Tasks 1.2-1.3.
