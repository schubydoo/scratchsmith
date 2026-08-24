/* Demo payload for the README asciinema cast: a tiny dynamic glibc binary that
 * also does an NSS lookup, so packing it exercises the loader + libc + NSS path,
 * not just a single-file copy. Built by record.sh. */
#include <netdb.h>
#include <stdio.h>

int main(void) {
    puts("hello from a FROM scratch image \xF0\x9F\x94\xA8");
    /* Fail loud if NSS is broken — this is the one thing the payload exists to
     * prove, so a regression must abort (via --smoke / set -e) rather than
     * quietly bake a clean-looking cast that resolved nothing. */
    struct addrinfo *res = NULL;
    int rc = getaddrinfo("localhost", NULL, NULL, &res);
    if (rc != 0) {
        fprintf(stderr, "NSS lookup failed: %s\n", gai_strerror(rc));
        return 1;
    }
    puts("glibc NSS resolved localhost inside scratch");
    freeaddrinfo(res);
    return 0;
}
