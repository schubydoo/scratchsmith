/* Demo payload for the README asciinema cast: a tiny dynamic glibc binary that
 * also does an NSS lookup, so packing it exercises the loader + libc + NSS path,
 * not just a single-file copy. Built by record.sh. */
#include <netdb.h>
#include <stdio.h>

int main(void) {
    puts("hello from a FROM scratch image \xF0\x9F\x94\xA8");
    struct addrinfo *res = NULL;
    if (getaddrinfo("localhost", NULL, NULL, &res) == 0) {
        puts("glibc NSS resolved localhost inside scratch");
        freeaddrinfo(res);
    }
    return 0;
}
