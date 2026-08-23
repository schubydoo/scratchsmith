//! Assemble the OCI image: reproducible layer tar, config, and manifest. Keeps the
//! diff_id (uncompressed) vs layer digest (gzip) distinction straight. See Tasks 1.6, 2.9.
